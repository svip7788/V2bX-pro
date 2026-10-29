package node

import (
	"context"
	"errors"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/task"
	"github.com/InazumaV/V2bX/common/violation"
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
	if c.LimitConfig.EnableDynamicSpeedLimit {
		if c.LimitConfig.DynamicSpeedLimitConfig == nil {
			log.WithField("tag", c.tag).Warn("DynamicSpeedLimitConfig is nil, skip dynamic speed limit task")
			return
		}
		triggerTime := c.LimitConfig.DynamicSpeedLimitConfig.DyLimitTriggerTime
		if triggerTime <= 0 {
			triggerTime = 60
		}
		c.traffic = make(map[string]int64)
		c.dynamicSpeedLimitPeriodic = &task.Task{
			Interval: time.Duration(triggerTime) * time.Second,
			Execute:  c.SpeedChecker,
		}
		log.Printf("[%s: %d] Start dynamic speed limit", c.apiClient.NodeType, c.apiClient.NodeId)
		_ = c.dynamicSpeedLimitPeriodic.Start(false)
	}
}

func (c *Controller) periodicNodeInfoMonitor() error {
	if c.isWebSocketConnected() && !c.reloadFailed.Load() {
		return nil
	}
	return c.nodeInfoMonitor()
}

func (c *Controller) nodeInfoMonitor() (err error) {
	c.runtimeMu.Lock()
	defer c.runtimeMu.Unlock()

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
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Get node info failed")
		return nil
	}
	// get user info
	newU, err := c.apiClient.GetUserList(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Get user list failed")
		return nil
	}
	// get user alive
	newA, err := c.apiClient.GetUserAlive(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Warn("Get alive list failed, keep old alive list")
		newA = nil
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
		c.traffic = make(map[string]int64)
		// Remove old node
		log.WithField("tag", c.tag).Info("Node changed, reload")
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

func (c *Controller) SpeedChecker() error {
	c.runtimeMu.Lock()
	defer c.runtimeMu.Unlock()
	cfg := c.LimitConfig.DynamicSpeedLimitConfig
	if !c.LimitConfig.EnableDynamicSpeedLimit || cfg == nil {
		return nil
	}
	if !c.limiter.InDynamicLimitTimeRange() {
		c.traffic = make(map[string]int64)
		return nil
	}
	triggerTime := cfg.DyLimitTriggerTime
	if triggerTime <= 0 {
		triggerTime = 60
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
		avgBytesPerSec := totalBytes / int64(triggerTime)
		if avgBytesPerSec >= triggerSpeedBytes {
			err := c.limiter.UpdateDynamicSpeedLimit(c.tag, uuid,
				limitSpeed,
				time.Now().Add(time.Duration(limitTime)*time.Second))
			if err != nil {
				log.WithField("err", err).Error("Update dynamic speed limit failed")
			} else {
				log.WithFields(log.Fields{
					"tag":  c.tag,
					"uuid": uuid,
					"avg":  avgBytesPerSec * 8 / 1000000,
				}).Info("Dynamic speed limit triggered")
			}
		}
	}
	c.traffic = make(map[string]int64)
	return nil
}
