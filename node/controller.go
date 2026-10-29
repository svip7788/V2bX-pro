package node

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/portreserve"
	"github.com/InazumaV/V2bX/common/task"
	"github.com/InazumaV/V2bX/common/violation"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/limiter"
	log "github.com/sirupsen/logrus"
)

type Controller struct {
	server                    vCore.Core
	apiClient                 *panel.Client
	tag                       string
	limiter                   *limiter.Limiter
	traffic                   map[string]int64
	userList                  []panel.UserInfo
	uidToUUID                 map[int]string
	aliveMap                  map[int]int
	info                      *panel.NodeInfo
	nodeInfoMonitorPeriodic   *task.Task
	userReportPeriodic        *task.Task
	renewCertPeriodic         *task.Task
	dynamicSpeedLimitPeriodic *task.Task
	onlineIpReportPeriodic    *task.Task
	wsClient                  *panel.WSClient
	wsConnected               func() bool
	wsStopCh                  chan struct{}
	machineWS                 MachineWSBridge
	machineEvents             chan panel.WSEvent
	machineEventsDropped      atomic.Bool
	configReloadPending       atomic.Bool
	// 重载时已删掉旧入站但未成功加回，需按拉取间隔重试，不能依赖配置是否变化
	reloadFailed atomic.Bool
	runtimeMu    sync.Mutex
	ctx          context.Context
	cancel       context.CancelFunc
	*conf.Options
}

// NewController return a Node controller with default parameters.
func NewController(server vCore.Core, api *panel.Client, config *conf.Options) *Controller {
	ctx, cancel := context.WithCancel(context.Background())
	controller := &Controller{
		server:    server,
		Options:   config,
		apiClient: api,
		ctx:       ctx,
		cancel:    cancel,
	}
	return controller
}

// Start implement the Start() function of the service interface
func (c *Controller) Start() error {
	// First fetch Node Info
	var err error
	ctx := c.currentCtx()
	node, err := c.apiClient.GetNodeInfo(ctx)
	if err != nil {
		return fmt.Errorf("get node info error: %s", err)
	}
	reservePort(node)
	// Update user
	c.userList, err = c.apiClient.GetUserList(ctx)
	if err != nil {
		return fmt.Errorf("get user list error: %s", err)
	}
	c.aliveMap, err = c.apiClient.GetUserAlive(ctx)
	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Warn("Get user alive list failed, fallback to empty alive list")
		c.aliveMap = make(map[int]int)
	}
	if len(c.Options.Name) == 0 {
		c.tag = c.buildNodeTag(node)
	} else {
		c.tag = c.Options.Name
	}

	// add limiter
	l := limiter.AddLimiter(c.tag, &c.LimitConfig, c.userList, c.aliveMap)
	// add rule limiter
	if err = l.UpdateRule(&node.Rules); err != nil {
		return fmt.Errorf("update rule error: %s", err)
	}
	c.limiter = l
	c.registerViolationSink()
	c.info = node
	c.applyPanelCertConfig(node)
	if node.Security == panel.Tls {
		err = c.requestCert()
		if err != nil {
			return fmt.Errorf("request cert error: %s", err)
		}
	}
	// Add new tag
	err = c.server.AddNode(c.tag, node, c.Options)
	if err != nil {
		return fmt.Errorf("add new node error: %s", err)
	}
	if len(c.userList) > 0 {
		added, err := c.server.AddUsers(&vCore.AddUsersParams{
			Tag:      c.tag,
			Users:    c.userList,
			NodeInfo: node,
		})
		if err != nil {
			return fmt.Errorf("add users error: %s", err)
		}
		log.WithField("tag", c.tag).Infof("Added %d new users", added)
	} else {
		log.WithField("tag", c.tag).Warn("No available users, node started with empty user list")
	}
	c.info = node
	c.rebuildUIDToUUID()
	c.startTasks(node)
	if c.machineWS != nil {
		c.startMachineEventLoop()
	} else {
		c.tryStartWebSocket()
	}
	return nil
}

func (c *Controller) registerViolationSink() {
	violation.Register(c.tag, func(items []violation.Item) error {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return c.apiClient.ReportViolations(ctx, items)
	})
}

// MachineWSBridge 机器模式下共享的 WS 连接
type MachineWSBridge interface {
	IsConnected() bool
	SendNodeDeviceReport(nodeID int, data map[int][]string)
}

// AttachMachineWS 须在 Start 之前调用，之后该节点不再自建 WS 连接
func (c *Controller) AttachMachineWS(bridge MachineWSBridge) {
	c.machineWS = bridge
	c.machineEvents = make(chan panel.WSEvent, 64)
}

// DispatchWSEvent 由机器管理器转发属于本节点的事件，不阻塞
func (c *Controller) DispatchWSEvent(evt panel.WSEvent) {
	if c.machineEvents == nil {
		return
	}
	select {
	case c.machineEvents <- evt:
	default:
		c.machineEventsDropped.Store(true)
		log.WithField("tag", c.tag).Warn("Machine WS event queue full, dropping event: ", evt.Event)
	}
}

func (c *Controller) startMachineEventLoop() {
	c.wsStopCh = make(chan struct{})
	go func(stop <-chan struct{}) {
		for {
			select {
			case <-stop:
				return
			case evt := <-c.machineEvents:
				c.processWSEvent(evt)
				if c.machineEventsDropped.Swap(false) {
					log.WithField("tag", c.tag).Warn("WS events were dropped, triggering full sync")
					if err := c.nodeInfoMonitor(); err != nil {
						log.WithField("err", err).Warn("Full sync after WS drop failed")
					}
				}
			}
		}
	}(c.wsStopCh)
}

func (c *Controller) sendDeviceReport(aliveData map[int][]string) {
	if len(aliveData) == 0 {
		return
	}
	if c.machineWS != nil {
		if c.machineWS.IsConnected() {
			c.machineWS.SendNodeDeviceReport(c.apiClient.NodeId, aliveData)
		}
		return
	}
	if c.wsClient != nil && c.wsClient.IsConnected() {
		c.wsClient.SendDeviceReport(aliveData)
	}
}

// Close implement the Close() function of the service interface
func (c *Controller) Close() error {
	if c.cancel != nil {
		c.cancel()
	}
	if c.wsStopCh != nil {
		close(c.wsStopCh)
	}
	if c.wsClient != nil {
		c.wsClient.Close()
	}
	limiter.DeleteLimiter(c.tag)
	violation.Unregister(c.tag)
	if c.nodeInfoMonitorPeriodic != nil {
		c.nodeInfoMonitorPeriodic.Close()
	}
	if c.userReportPeriodic != nil {
		c.userReportPeriodic.Close()
	}
	if c.renewCertPeriodic != nil {
		c.renewCertPeriodic.Close()
	}
	if c.dynamicSpeedLimitPeriodic != nil {
		c.dynamicSpeedLimitPeriodic.Close()
	}
	if c.onlineIpReportPeriodic != nil {
		c.onlineIpReportPeriodic.Close()
	}
	err := c.server.DelNode(c.tag)
	if err != nil {
		return fmt.Errorf("del node error: %s", err)
	}
	return nil
}

func (c *Controller) buildNodeTag(node *panel.NodeInfo) string {
	return fmt.Sprintf("[%s]-%s:%d", c.apiClient.APIHost, node.Type, node.Id)
}

// currentCtx returns a usable context even if the Controller was constructed
// without NewController (e.g. from tests with hand-built struct literals).
func (c *Controller) currentCtx() context.Context {
	if c.ctx != nil {
		return c.ctx
	}
	return context.Background()
}

func (c *Controller) isWebSocketConnected() bool {
	if c.wsConnected != nil {
		return c.wsConnected()
	}
	if c.machineWS != nil {
		return c.machineWS.IsConnected()
	}
	return c.wsClient != nil && c.wsClient.IsConnected()
}

func (c *Controller) tryStartWebSocket() {
	resp, err := c.apiClient.Handshake()
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Info("WS handshake failed, using HTTP polling only")
		return
	}
	if !resp.Websocket.Enabled || resp.Websocket.WsURL == "" {
		log.WithField("tag", c.tag).Info("WS not enabled by panel, using HTTP polling only")
		return
	}
	ws, err := c.apiClient.NewWSClient(resp.Websocket.WsURL)
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Warn("WS connect failed, using HTTP polling only")
		return
	}
	c.wsClient = ws
	c.wsStopCh = make(chan struct{})
	go c.handleWSEvents()
	log.WithField("tag", c.tag).Info("WS real-time push enabled")
}

func (c *Controller) handleWSEvents() {
	for {
		select {
		case <-c.wsStopCh:
			return
		case evt, ok := <-c.wsClient.Events():
			if !ok {
				return
			}
			c.processWSEvent(evt)
			if c.wsClient.DroppedAndReset() {
				log.WithField("tag", c.tag).Warn("WS events were dropped, triggering full sync")
				if err := c.nodeInfoMonitor(); err != nil {
					log.WithField("err", err).Warn("Full sync after WS drop failed")
				}
			}
		}
	}
}

func (c *Controller) processWSEvent(evt panel.WSEvent) {
	switch evt.Event {
	case "sync.config":
		c.scheduleConfigReload()
		return
	}

	c.runtimeMu.Lock()
	defer c.runtimeMu.Unlock()

	switch evt.Event {
	case "sync.users":
		var data panel.WSUsersData
		if err := json.Unmarshal(evt.Data, &data); err != nil {
			log.WithField("err", err).Warn("WS: unmarshal sync.users failed")
			return
		}
		c.applyFullUsers(data.Users)

	case "sync.user.delta":
		var data panel.WSUserDeltaData
		if err := json.Unmarshal(evt.Data, &data); err != nil {
			log.WithField("err", err).Warn("WS: unmarshal sync.user.delta failed")
			return
		}
		c.applyUserDelta(data.Action, data.Users)

	case "sync.devices":
		var data panel.WSDevicesData
		if err := json.Unmarshal(evt.Data, &data); err != nil {
			log.WithField("err", err).Warn("WS: unmarshal sync.devices failed")
			return
		}
		alive := make(map[int]int, len(data.Users))
		for uidStr, ips := range data.Users {
			var uid int
			fmt.Sscanf(uidStr, "%d", &uid)
			alive[uid] = len(ips)
		}
		c.limiter.SetAliveList(alive)
		c.aliveMap = alive
	}
}

// 连上面板时面板推一次 sync.config、重连本身也触发一次，合并成一次拉取；
// 随机延迟错开整批节点对面板的 HTTP 请求
func (c *Controller) scheduleConfigReload() {
	if !c.configReloadPending.CompareAndSwap(false, true) {
		return
	}
	delay := time.Second + time.Duration(rand.Int63n(int64(3*time.Second)))
	time.AfterFunc(delay, func() {
		c.configReloadPending.Store(false)
		log.WithField("tag", c.tag).Info("WS: received config push, triggering reload")
		if err := c.nodeInfoMonitor(); err != nil {
			log.WithField("err", err).Warn("WS: nodeInfoMonitor failed after sync.config")
		}
	})
}

func (c *Controller) applyFullUsers(newUsers []panel.UserInfo) {
	if err := c.syncUsersLocked(newUsers, "WS"); err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("WS: sync users failed")
	}
}

func (c *Controller) applyUserDelta(action string, users []panel.UserInfo) {
	switch action {
	case "add":
		if len(users) == 0 {
			return
		}
		existSet := make(map[string]struct{}, len(c.userList))
		for _, u := range c.userList {
			existSet[u.Uuid] = struct{}{}
		}
		var newUsers []panel.UserInfo
		for _, u := range users {
			if _, dup := existSet[u.Uuid]; !dup {
				newUsers = append(newUsers, u)
			}
		}
		if len(newUsers) == 0 {
			return
		}
		if err := c.applyUserChangesLocked(newUsers, nil); err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("WS: add users failed")
			return
		}
		c.userList = append(cloneUserList(c.userList), newUsers...)
		c.rebuildUIDToUUID()
		log.WithField("tag", c.tag).Infof("WS: delta added %d users", len(newUsers))

	case "remove":
		if len(users) == 0 {
			return
		}
		// 面板的 remove 只保证带 id，uuid 需从本地列表补全（内核按 uuid 删用户）
		removeIDs := make(map[int]struct{}, len(users))
		removeUUIDs := make(map[string]struct{}, len(users))
		for _, u := range users {
			if u.Id > 0 {
				removeIDs[u.Id] = struct{}{}
			}
			if u.Uuid != "" {
				removeUUIDs[u.Uuid] = struct{}{}
			}
		}
		var matched []panel.UserInfo
		filtered := make([]panel.UserInfo, 0, len(c.userList))
		for _, u := range c.userList {
			_, byID := removeIDs[u.Id]
			_, byUUID := removeUUIDs[u.Uuid]
			if byID || byUUID {
				matched = append(matched, u)
			} else {
				filtered = append(filtered, u)
			}
		}
		if len(matched) == 0 {
			return
		}
		if err := c.applyUserChangesLocked(nil, matched); err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("WS: remove users failed")
			return
		}
		c.userList = filtered
		c.rebuildUIDToUUID()
		log.WithField("tag", c.tag).Infof("WS: delta removed %d users", len(matched))
	}
}

func cloneUserList(users []panel.UserInfo) []panel.UserInfo {
	if len(users) == 0 {
		return nil
	}
	cloned := make([]panel.UserInfo, len(users))
	copy(cloned, users)
	return cloned
}

func (c *Controller) clearDynamicTrafficLocked(users []panel.UserInfo) {
	if !c.LimitConfig.EnableDynamicSpeedLimit || len(users) == 0 {
		return
	}
	for i := range users {
		delete(c.traffic, users[i].Uuid)
	}
}

func (c *Controller) applyUserChangesLocked(added, deleted []panel.UserInfo) error {
	if len(deleted) > 0 {
		if err := c.server.DelUsers(deleted, c.tag, c.info); err != nil {
			return fmt.Errorf("delete users error: %w", err)
		}
	}
	if len(added) > 0 {
		if _, err := c.server.AddUsers(&vCore.AddUsersParams{
			Tag:      c.tag,
			NodeInfo: c.info,
			Users:    added,
		}); err != nil {
			return fmt.Errorf("add users error: %w", err)
		}
	}
	if len(added) > 0 || len(deleted) > 0 {
		c.limiter.UpdateUser(c.tag, added, deleted)
		c.clearDynamicTrafficLocked(deleted)
	}
	return nil
}

func (c *Controller) syncUsersLocked(newUsers []panel.UserInfo, source string) error {
	nextUsers := cloneUserList(newUsers)
	deleted, added := compareUserList(c.userList, nextUsers)
	if err := c.applyUserChangesLocked(added, deleted); err != nil {
		return err
	}
	c.userList = nextUsers
	c.rebuildUIDToUUID()
	if len(added) > 0 || len(deleted) > 0 {
		log.WithField("tag", c.tag).
			Infof("%s: %d user deleted, %d user added", source, len(deleted), len(added))
	}
	return nil
}

func (c *Controller) applyPanelCertConfig(node *panel.NodeInfo) {
	if node.CertConfig == nil {
		return
	}
	pc := node.CertConfig
	if pc.CertMode != "" {
		c.CertConfig.CertMode = pc.CertMode
	}
	if pc.CertFile != "" {
		c.CertConfig.CertFile = pc.CertFile
	}
	if pc.KeyFile != "" {
		c.CertConfig.KeyFile = pc.KeyFile
	}
	if pc.CertDomain != "" {
		c.CertConfig.CertDomain = pc.CertDomain
	}
	if pc.Provider != "" {
		c.CertConfig.Provider = pc.Provider
	}
	if pc.Email != "" {
		c.CertConfig.Email = pc.Email
	}
	c.CertConfig.RejectUnknownSni = pc.RejectUnknownSni
	log.WithField("tag", c.tag).Info("Applied cert config from panel")
}

func reservePort(node *panel.NodeInfo) {
	if node == nil || node.Common == nil {
		return
	}
	if err := portreserve.Reserve(node.Common.ServerPort); err != nil {
		log.WithFields(log.Fields{
			"port": node.Common.ServerPort,
			"err":  err,
		}).Warn("Reserve listen port failed")
	}
}
