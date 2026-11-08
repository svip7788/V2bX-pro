package node

import (
	"fmt"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/ipwatch"
	"github.com/InazumaV/V2bX/common/task"
	"github.com/InazumaV/V2bX/common/violation"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/limiter"
	log "github.com/sirupsen/logrus"
)

func (c *Controller) startTasks(node *panel.NodeInfo) {
	// fetch node info task
	c.nodeInfoMonitorPeriodic = &task.Task{
		Interval: node.PullInterval,
		Execute:  c.periodicNodeInfoMonitor,
	}
	// fetch user list task
	c.userReportPeriodic = &task.Task{
		Interval: node.PushInterval,
		Execute:  c.reportUserTrafficTask,
	}
	log.WithField("tag", c.tag).Info("Start monitor node status")
	// delay to start nodeInfoMonitor
	_ = c.nodeInfoMonitorPeriodic.Start(false)
	log.WithField("tag", c.tag).Info("Start report node status")
	_ = c.userReportPeriodic.Start(false)
	if node.Security == panel.Tls {
		switch c.CertConfig.CertMode {
		case "none", "", "file", "self":
		default:
			c.renewCertPeriodic = &task.Task{
				Interval: time.Hour * 24,
				Execute:  c.renewCertTask,
			}
			log.WithField("tag", c.tag).Info("Start renew cert")
			// delay to start renewCert
			_ = c.renewCertPeriodic.Start(true)
		}
	}
	c.resetDynamicTraffic()
	if c.LimitConfig.EnableDynamicSpeedLimit {
		log.Printf("[%s: %d] Start dynamic speed limit", c.apiClient.NodeType, c.apiClient.NodeId)
	}
}

// WS 推送是发完即忘的，面板也不会为「自然到期」推删除；WS 在线时仍需低频轮询兜底，
// 否则丢一条 remove 或用户到期后，节点会一直放行该用户。
const wsFallbackPollInterval = 5 * time.Minute

func (c *Controller) shouldPoll(now time.Time) bool {
	if !c.isWebSocketConnected() || c.reloadFailed.Load() {
		return true
	}
	return now.Sub(time.Unix(c.lastPollAt.Load(), 0)) >= wsFallbackPollInterval
}

func (c *Controller) periodicNodeInfoMonitor() error {
	if !c.shouldPoll(time.Now()) || c.isGone() {
		return nil
	}
	return c.nodeInfoMonitor()
}

const (
	goneBackoffMin = 5 * time.Minute
	goneBackoffMax = 30 * time.Minute
)

func (c *Controller) isGone() bool {
	c.runtimeMu.Lock()
	defer c.runtimeMu.Unlock()
	return time.Now().Before(c.goneUntil)
}

// markGone 需持有 runtimeMu
func (c *Controller) markGone() {
	c.goneBackoff = min(max(c.goneBackoff*2, goneBackoffMin), goneBackoffMax)
	c.goneUntil = time.Now().Add(c.goneBackoff)
	log.WithFields(log.Fields{
		"tag":   c.tag,
		"retry": c.goneBackoff,
	}).Error("Node does not exist on panel, remove it from config")
}

func (c *Controller) nodeInfoMonitor() (err error) {
	c.runtimeMu.Lock()
	defer c.runtimeMu.Unlock()
	c.lastPollAt.Store(time.Now().Unix())

	ctx := c.currentCtx()
	if ctx.Err() != nil {
		return nil
	}

	retrying := c.reloadFailed.Load()
	if retrying {
		c.apiClient.ResetNodeInfoCache()
	}
	// get node info
	newN, err := c.apiClient.GetNodeInfo(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		if panel.IsNodeNotExist(err) {
			c.markGone()
			return nil
		}
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Get node info failed")
		return nil
	}
	c.goneBackoff = 0
	c.goneUntil = time.Time{}
	// get user info
	newU, err := c.apiClient.GetUserList(ctx)
	if err != nil {
		// 节点配置已按 ETag 记为已取，不重置的话本次变更会被下次 304 吞掉
		if newN != nil {
			c.apiClient.ResetNodeInfoCache()
		}
		if ctx.Err() != nil {
			return nil
		}
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Get user list failed")
		return nil
	}
	if newU != nil {
		newU = c.keepRecentWSChanges(newU, c.apiClient.UserListAt())
	}
	// get user alive
	newA, err := c.apiClient.GetUserAlive(ctx)
	if err != nil {
		if ctx.Err() != nil {
			if newN != nil {
				c.apiClient.ResetNodeInfoCache()
			}
			return nil
		}
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Warn("Get alive list failed, keep old alive list")
		newA = nil
	}
	// 只改了限速/监控策略：原地生效，不重建入站，避免断开所有用户
	if newN != nil && !retrying && c.info != nil && newN.CoreHash != "" && newN.CoreHash == c.info.CoreHash {
		c.info = newN
		c.applyDynamicSpeedLimit(newN)
		c.applyIPWatch(newN)
		c.limiter.SetDynamicConfig(&c.LimitConfig)
		c.resetDynamicTraffic()
		log.WithField("tag", c.tag).Info("Node policy changed, applied without reload")
		newN = nil
	}
	if newN != nil {
		oldUsers := cloneUserList(c.userList)
		nextUsers := c.userList
		if newU != nil {
			nextUsers = cloneUserList(newU)
		}
		c.info = newN
		c.userList = nextUsers
		c.rebuildUIDToUUID()
		c.applyDynamicSpeedLimit(newN)
		c.applyIPWatch(newN)
		c.resetDynamicTraffic()
		// Remove old node
		log.WithField("tag", c.tag).Info("Node changed, reload")
		c.stashTraffic()
		err = c.server.DelNode(c.tag)
		if err != nil && !retrying {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Delete node failed, will retry")
			c.reloadFailed.Store(true)
			return nil
		}
		c.reloadFailed.Store(true)

		// Update limiter
		if len(c.Options.Name) == 0 {
			oldTag := c.tag
			c.tag = c.buildNodeTag(newN)
			limiter.DeleteLimiter(oldTag)
			violation.Unregister(oldTag)
			c.registerViolationSink()
			aliveList := newA
			if aliveList == nil {
				aliveList = c.aliveMap
			}
			l := limiter.AddLimiter(c.tag, &c.LimitConfig, c.userList, aliveList)
			c.limiter = l
		} else if newU != nil {
			deleted, added := compareUserList(oldUsers, nextUsers)
			if len(added) > 0 || len(deleted) > 0 {
				c.limiter.UpdateUser(c.tag, added, deleted)
			}
		}
		c.limiter.SetDynamicConfig(&c.LimitConfig)
		// update alive list
		if newA != nil {
			c.limiter.SetAliveList(newA)
			c.aliveMap = newA
		}
		// Update rule
		err = c.limiter.UpdateRule(&newN.Rules)
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Update Rule failed")
			return nil
		}

		// check cert
		c.applyPanelCertConfig(newN)
		if newN.Security == panel.Tls {
			err = c.requestCert()
			if err != nil {
				log.WithFields(log.Fields{
					"tag": c.tag,
					"err": err,
				}).Error("Request cert failed")
				return nil
			}
		}
		// add new node
		reservePort(newN)
		err = c.server.AddNode(c.tag, newN, c.Options)
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Add node failed, will retry")
			return nil
		}
		if len(c.userList) > 0 {
			_, err = c.server.AddUsers(&vCore.AddUsersParams{
				Tag:      c.tag,
				Users:    c.userList,
				NodeInfo: newN,
			})
			if err != nil {
				log.WithFields(log.Fields{
					"tag": c.tag,
					"err": err,
				}).Error("Add users failed, will retry")
				return nil
			}
		}
		c.reloadFailed.Store(false)
		// Check interval
		if c.nodeInfoMonitorPeriodic.Interval != newN.PullInterval &&
			newN.PullInterval != 0 {
			c.nodeInfoMonitorPeriodic.Restart(newN.PullInterval)
		}
		if c.userReportPeriodic.Interval != newN.PushInterval &&
			newN.PushInterval != 0 {
			c.userReportPeriodic.Restart(newN.PushInterval)
		}
		log.WithField("tag", c.tag).Infof("Reloaded node with %d users", len(c.userList))
		// exit
		return nil
	}
	// update alive list
	if newA != nil {
		c.limiter.SetAliveList(newA)
		c.aliveMap = newA
	}
	// node no changed, check users
	if newU == nil {
		return nil
	}
	if err := c.syncUsersLocked(newU, "Poll"); err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Sync users failed")
	}
	return nil
}

type localDynamicConfig struct {
	enable bool
	cfg    *conf.DynamicSpeedLimitConfig
}

// applyDynamicSpeedLimit 面板下发了 dynamic_speed_limit 就以面板为准，否则回落到本地配置
func (c *Controller) applyDynamicSpeedLimit(n *panel.NodeInfo) {
	if c.localDynamic == nil {
		c.localDynamic = &localDynamicConfig{
			enable: c.LimitConfig.EnableDynamicSpeedLimit,
			cfg:    c.LimitConfig.DynamicSpeedLimitConfig,
		}
	}
	enable, cfg := c.localDynamic.enable, c.localDynamic.cfg
	c.dynamicGlobal = n.DynamicSpeedLimit != nil && n.DynamicSpeedLimit.Global
	if d := n.DynamicSpeedLimit; d != nil {
		enable = d.Enable
		cfg = &conf.DynamicSpeedLimitConfig{
			DyLimitDuration:     d.Periods,
			DyLimitTriggerTime:  d.TriggerTime,
			DyLimitTriggerSpeed: d.TriggerSpeed,
			DyLimitSpeed:        d.LimitSpeed,
			DyLimitTime:         d.LimitTime,
			DyLimitWhiteUserID:  d.WhiteUserIDs,
		}
	}
	enable = enable && cfg != nil
	if enable != c.LimitConfig.EnableDynamicSpeedLimit {
		log.WithFields(log.Fields{"tag": c.tag, "enable": enable, "panel": n.DynamicSpeedLimit != nil}).
			Info("Dynamic speed limit changed")
	}
	c.LimitConfig.EnableDynamicSpeedLimit = enable
	c.LimitConfig.DynamicSpeedLimitConfig = cfg
}

func (c *Controller) applyIPWatch(n *panel.NodeInfo) {
	var m *ipwatch.Matcher
	if w := n.IPWatch; w != nil && w.Enable {
		m = ipwatch.New(w.Targets, w.Threshold)
	}
	ipwatch.Set(c.tag, m)
}

// limitUserSpeed 对用户施加动态限速；限速桶在建连时取定，断开现有连接让重连后立即按新限速走
func (c *Controller) limitUserSpeed(uuid string, limitSpeed, limitTime int) (int, error) {
	err := c.limiter.UpdateDynamicSpeedLimit(c.tag, uuid, limitSpeed, time.Now().Add(time.Duration(limitTime)*time.Second))
	if err != nil {
		return 0, err
	}
	return c.server.CloseUserConns(c.tag, uuid), nil
}

func (c *Controller) resetDynamicTraffic() {
	c.traffic = make(map[string]int64)
	c.trafficSince = time.Now()
}

// checkDynamicSpeed 在流量上报后调用，按两次检测间的实际时长求均速，不受上报间隔影响
func (c *Controller) checkDynamicSpeed() {
	cfg := c.LimitConfig.DynamicSpeedLimitConfig
	if !c.LimitConfig.EnableDynamicSpeedLimit || cfg == nil {
		return
	}
	// 面板汇总模式下由面板判定并下发；WS 断开收不到下发时才按本节点流量兜底
	if !c.limiter.InDynamicLimitTimeRange() || (c.dynamicGlobal && c.isWebSocketConnected()) {
		c.resetDynamicTraffic()
		return
	}
	triggerTime := cfg.DyLimitTriggerTime
	if triggerTime <= 0 {
		triggerTime = 60
	}
	// 上报由 ticker 驱动但 HTTP 耗时有抖动，留半个上报间隔余量，避免刚好差一点而多等一轮
	var slack time.Duration
	if c.info != nil {
		slack = c.info.PushInterval / 2
	}
	since := time.Since(c.trafficSince)
	if since+slack < time.Duration(triggerTime)*time.Second {
		return
	}
	elapsed := int64(since / time.Second)
	if elapsed <= 0 {
		return
	}
	triggerSpeed := cfg.DyLimitTriggerSpeed
	if triggerSpeed <= 0 {
		triggerSpeed = 100
	}
	triggerSpeedBytes := int64(triggerSpeed) * 1000000 / 8 // Mbps -> bytes/s
	limitTime := cfg.DyLimitTime
	if limitTime <= 0 {
		limitTime = 600
	}
	limitSpeed := cfg.DyLimitSpeed
	if limitSpeed <= 0 {
		limitSpeed = 30
	}

	for uuid, totalBytes := range c.traffic {
		uid, ok := c.limiter.GetUIDByUUID(uuid)
		if !ok {
			continue
		}
		if c.limiter.IsWhitelisted(uid) {
			continue
		}
		if c.limiter.IsDynamicLimited(c.tag, uuid) {
			continue
		}
		avgBytesPerSec := totalBytes / elapsed
		if avgBytesPerSec >= triggerSpeedBytes {
			closed, err := c.limitUserSpeed(uuid, limitSpeed, limitTime)
			if err != nil {
				log.WithField("err", err).Error("Update dynamic speed limit failed")
			} else {
				avgMbps := avgBytesPerSec * 8 / 1000000
				violation.Report(c.tag, violation.Item{
					UID:    uid,
					Kind:   violation.KindSpeed,
					Target: fmt.Sprintf("%dMbps", avgMbps),
					Detail: fmt.Sprintf("%d 秒均速 %dMbps，限速 %dMbps %d 分钟", elapsed, avgMbps, limitSpeed, (limitTime+59)/60),
				})
				log.WithFields(log.Fields{
					"tag":    c.tag,
					"uid":    uid,
					"avg":    avgMbps,
					"limit":  limitSpeed,
					"closed": closed,
				}).Info("Dynamic speed limit triggered")
			}
		}
	}
	c.resetDynamicTraffic()
}
