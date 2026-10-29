package machine

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/node"
	log "github.com/sirupsen/logrus"
)

const (
	defaultPullInterval = 60 * time.Second
	wsPullInterval      = 5 * time.Minute
	statusInterval      = 60 * time.Second
)

type runningNode struct {
	key  string
	ctrl *node.Controller
}

// Manager 机器模式：按面板下发的节点列表增量启停节点，共用一条 WS 连接
type Manager struct {
	cfg       *conf.MachineConfig
	core      vCore.Core
	coreTypes []string
	client    *panel.MachineClient
	version   string

	wsMu sync.RWMutex
	ws   *panel.WSClient

	mu    sync.RWMutex
	nodes map[int]*runningNode

	syncMu       sync.Mutex
	syncCh       chan struct{}
	pendingMu    sync.Mutex
	pendingNodes []panel.MachineNode
	hasPending   bool
	pullInterval atomic.Int64
	// 有节点启动失败时不走 WS 下的长拉取间隔，尽快重试
	hasFailedNodes atomic.Bool

	commands *commandRunner
	terms    *terminals
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func NewManager(cfg *conf.MachineConfig, core vCore.Core, coreTypes []string, version string) (*Manager, error) {
	client, err := panel.NewMachineClient(cfg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		cfg:       cfg,
		core:      core,
		coreTypes: coreTypes,
		client:    client,
		version:   version,
		nodes:     make(map[int]*runningNode),
		syncCh:    make(chan struct{}, 1),
		ctx:       ctx,
		cancel:    cancel,
	}
	m.pullInterval.Store(int64(defaultPullInterval))
	m.commands = newCommandRunner(m)
	m.terms = newTerminals(m)
	return m, nil
}

// Start 面板暂时不可达时不报错，后台持续重试
func (m *Manager) Start() {
	m.connectWS()
	m.syncNodes(nil)
	m.wg.Add(3)
	go m.syncLoop()
	go m.pullLoop()
	go m.statusLoop()
	log.WithFields(log.Fields{"machine_id": m.cfg.MachineID, "panel": m.cfg.APIHost}).Info("Machine mode started")
}

func (m *Manager) Close() {
	m.cancel()
	if ws := m.wsClient(); ws != nil {
		ws.Close()
	}
	m.wg.Wait()
	m.syncMu.Lock()
	defer m.syncMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, n := range m.nodes {
		if err := n.ctrl.Close(); err != nil {
			log.WithFields(log.Fields{"node_id": id, "err": err}).Error("Close node failed")
		}
	}
	m.nodes = map[int]*runningNode{}
}

func (m *Manager) wsClient() *panel.WSClient {
	m.wsMu.RLock()
	defer m.wsMu.RUnlock()
	return m.ws
}

// IsConnected / SendNodeDeviceReport 实现 node.MachineWSBridge
func (m *Manager) IsConnected() bool {
	ws := m.wsClient()
	return ws != nil && ws.IsConnected()
}

func (m *Manager) SendNodeDeviceReport(nodeID int, data map[int][]string) {
	if ws := m.wsClient(); ws != nil {
		ws.SendNodeDeviceReport(nodeID, data)
	}
}

func (m *Manager) send(event string, data any) {
	if ws := m.wsClient(); ws != nil {
		ws.Send(event, data)
	}
}

func (m *Manager) connectWS() {
	if m.wsClient() != nil {
		return
	}
	resp, err := m.client.Handshake()
	if err != nil {
		log.WithField("err", err).Warn("Machine handshake failed, using HTTP polling only")
		return
	}
	if !resp.Websocket.Enabled || resp.Websocket.WsURL == "" {
		log.Info("WS not enabled by panel, using HTTP polling only")
		return
	}
	ws, err := m.client.NewWSClient(resp.Websocket.WsURL)
	if err != nil {
		log.WithField("err", err).Warn("Machine WS connect failed, will retry later")
		return
	}
	ws.SetDirectHandler(func(evt panel.WSEvent) bool {
		return m.terms.handle(evt.Event, evt.Data) || m.handleLive(evt)
	})
	m.wsMu.Lock()
	m.ws = ws
	m.wsMu.Unlock()
	m.wg.Add(1)
	go m.eventLoop(ws)
	log.Info("Machine WS connected")
}

// requestSync 合并触发；nodes 为 nil 表示需要 HTTP 拉取
func (m *Manager) requestSync(nodes []panel.MachineNode, fromPush bool) {
	m.pendingMu.Lock()
	if fromPush {
		m.pendingNodes = nodes
		m.hasPending = true
	}
	m.pendingMu.Unlock()
	select {
	case m.syncCh <- struct{}{}:
	default:
	}
}

func (m *Manager) syncLoop() {
	defer m.wg.Done()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-m.syncCh:
			m.pendingMu.Lock()
			nodes, has := m.pendingNodes, m.hasPending
			m.pendingNodes, m.hasPending = nil, false
			m.pendingMu.Unlock()
			if has {
				m.syncNodes(nodes)
			} else {
				m.syncNodes(nil)
			}
		}
	}
}

func (m *Manager) pullLoop() {
	defer m.wg.Done()
	for {
		interval := time.Duration(m.pullInterval.Load())
		if m.IsConnected() && !m.hasFailedNodes.Load() {
			interval = wsPullInterval
		}
		select {
		case <-m.ctx.Done():
			return
		case <-time.After(interval):
		}
		m.connectWS()
		m.requestSync(nil, false)
	}
}

type desiredNode struct {
	nodeType      string
	proxyProtocol bool
}

func nodeKey(id int, d desiredNode) string {
	return fmt.Sprintf("%d|%s|%t", id, d.nodeType, d.proxyProtocol)
}

// syncNodes nodes 为 nil 时从面板拉取
func (m *Manager) syncNodes(nodes []panel.MachineNode) {
	m.syncMu.Lock()
	defer m.syncMu.Unlock()
	if m.ctx.Err() != nil {
		return
	}
	if nodes == nil {
		resp, err := m.client.FetchNodes()
		if err != nil {
			log.WithField("err", err).Error("Fetch machine nodes failed")
			return
		}
		nodes = resp.Nodes
		if resp.BaseConfig.PullInterval > 0 {
			m.pullInterval.Store(int64(time.Duration(resp.BaseConfig.PullInterval) * time.Second))
		}
	}

	desired := make(map[int]desiredNode, len(nodes))
	for _, n := range nodes {
		t := n.NodeType
		if t == "" {
			t = n.Type
		}
		nt := conf.NormalizeMachineNodeType(t)
		if nt == "" {
			log.WithFields(log.Fields{"node_id": n.ID, "type": t}).Warn("Unsupported node type, skipped")
			continue
		}
		desired[n.ID] = desiredNode{nodeType: nt, proxyProtocol: n.ProxyProtocol}
	}

	m.mu.RLock()
	var stale []int
	for id, rn := range m.nodes {
		if d, ok := desired[id]; !ok || rn.key != nodeKey(id, d) {
			stale = append(stale, id)
		}
	}
	m.mu.RUnlock()
	for _, id := range stale {
		m.stopNode(id)
	}

	ids := make([]int, 0, len(desired))
	for id := range desired {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	failed := false
	for _, id := range ids {
		m.mu.RLock()
		_, running := m.nodes[id]
		m.mu.RUnlock()
		if running {
			continue
		}
		if err := m.startNode(id, desired[id]); err != nil {
			failed = true
			log.WithFields(log.Fields{"node_id": id, "type": desired[id].nodeType, "err": err}).
				Error("Start node failed, will retry on next sync")
		}
	}
	m.hasFailedNodes.Store(failed)
}

func (m *Manager) startNode(id int, d desiredNode) error {
	nodeType := d.nodeType
	coreType := m.cfg.CoreTypeFor(nodeType, m.coreTypes)
	nc, err := m.cfg.NodeConfig(id, nodeType, coreType)
	if err != nil {
		return err
	}
	if d.proxyProtocol && nc.Options.XrayOptions != nil {
		nc.Options.XrayOptions.EnableProxyProtocol = true
	}
	api, err := panel.NewMachineNode(&nc.ApiConfig, m.cfg.MachineID)
	if err != nil {
		return err
	}
	ctrl := node.NewController(m.core, api, &nc.Options)
	ctrl.AttachMachineWS(m)
	if err := ctrl.Start(); err != nil {
		_ = ctrl.Close()
		return err
	}
	m.mu.Lock()
	m.nodes[id] = &runningNode{key: nodeKey(id, d), ctrl: ctrl}
	m.mu.Unlock()
	log.WithFields(log.Fields{"node_id": id, "type": nodeType, "core": coreType, "proxy_protocol": d.proxyProtocol}).Info("Node started")
	return nil
}

func (m *Manager) stopNode(id int) {
	m.mu.Lock()
	rn, ok := m.nodes[id]
	delete(m.nodes, id)
	m.mu.Unlock()
	if !ok {
		return
	}
	if err := rn.ctrl.Close(); err != nil {
		log.WithFields(log.Fields{"node_id": id, "err": err}).Warn("Close node failed")
	}
	log.WithField("node_id", id).Info("Node stopped")
}

func (m *Manager) broadcast(evt panel.WSEvent) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, rn := range m.nodes {
		rn.ctrl.DispatchWSEvent(evt)
	}
}

func (m *Manager) eventLoop(ws *panel.WSClient) {
	defer m.wg.Done()
	for {
		select {
		case <-m.ctx.Done():
			return
		case evt, ok := <-ws.Events():
			if !ok {
				return
			}
			m.handleEvent(evt)
			if ws.DroppedAndReset() {
				log.Warn("Machine WS events were dropped, triggering full sync")
				m.requestSync(nil, false)
				m.broadcast(panel.WSEvent{Event: "sync.config"})
			}
		}
	}
}

func (m *Manager) handleEvent(evt panel.WSEvent) {
	switch evt.Event {
	case "sync.nodes":
		var data struct {
			Nodes []panel.MachineNode `json:"nodes"`
		}
		if err := json.Unmarshal(evt.Data, &data); err != nil {
			log.WithField("err", err).Warn("WS: unmarshal sync.nodes failed")
			m.requestSync(nil, false)
			return
		}
		if data.Nodes == nil {
			data.Nodes = []panel.MachineNode{}
		}
		m.requestSync(data.Nodes, true)
		return
	case "machine.command":
		m.commands.handle(evt.Data)
		return
	}

	var target struct {
		NodeID  int   `json:"node_id"`
		NodeIDs []int `json:"node_ids"`
	}
	if len(evt.Data) > 0 {
		_ = json.Unmarshal(evt.Data, &target)
	}
	if len(target.NodeIDs) > 0 {
		m.mu.RLock()
		defer m.mu.RUnlock()
		for _, id := range target.NodeIDs {
			if rn, ok := m.nodes[id]; ok {
				rn.ctrl.DispatchWSEvent(evt)
			}
		}
		return
	}
	if target.NodeID <= 0 {
		// 重连后的 sync.config 不带 node_id：节点列表与所有节点配置都需重新同步
		if evt.Event == "sync.config" {
			m.requestSync(nil, false)
			m.broadcast(evt)
		}
		return
	}
	m.mu.RLock()
	rn, ok := m.nodes[target.NodeID]
	m.mu.RUnlock()
	if !ok {
		log.WithFields(log.Fields{"node_id": target.NodeID, "event": evt.Event}).Debug("WS event for unknown node")
		return
	}
	rn.ctrl.DispatchWSEvent(evt)
}

func (m *Manager) statusLoop() {
	defer m.wg.Done()
	collector := newStatusCollector()
	report := func() {
		s := collector.collect()
		s.V2bX.Status = "active"
		s.V2bX.Version = m.currentVersion()
		if err := m.client.ReportStatus(s); err != nil {
			log.WithField("err", err).Warn("Report machine status failed")
		}
	}
	// 首次上报稍等，让网速采样有间隔
	select {
	case <-m.ctx.Done():
		return
	case <-time.After(5 * time.Second):
	}
	report()
	ticker := time.NewTicker(statusInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			report()
		}
	}
}

func (m *Manager) runningNodeIDs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := make([]int, 0, len(m.nodes))
	for id := range m.nodes {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = fmt.Sprintf("%d(%s)", id, strings.Split(m.nodes[id].key, "|")[1])
	}
	return out
}
