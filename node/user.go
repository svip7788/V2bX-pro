package node

import (
	"context"
	"errors"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	log "github.com/sirupsen/logrus"
)

func (c *Controller) reportUserTrafficTask() (err error) {
	c.runtimeMu.Lock()
	defer c.runtimeMu.Unlock()
	defer c.limiter.MarkOnlineDeviceReported()

	ctx := c.currentCtx()
	if ctx.Err() != nil || time.Now().Before(c.goneUntil) {
		return nil
	}

	userTraffic, trafficErr := c.server.GetUserTrafficSlice(c.tag, true)
	if trafficErr != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": trafficErr,
		}).Error("Get user traffic slice failed")
	}
	// 动态限速只看本轮新增流量，不受上报成败和积压补报影响
	if len(userTraffic) > 0 {
		c.addDynamicTraffic(userTraffic)
	}
	userTraffic = mergeTraffic(c.pendingTraffic, userTraffic)
	c.pendingTraffic = nil

	var aliveData map[int][]string
	var onlineDeviceCount int
	c.limiter.TouchActiveDevices(c.tag, c.server.ActiveUserIPs(c.tag))
	if onlineDevice, err := c.limiter.GetOnlineDevice(); err != nil {
		log.Print(err)
	} else if len(onlineDevice) > 0 {
		onlineDeviceCount = len(onlineDevice)
		var nocountUID map[int]struct{}
		if len(userTraffic) > 0 && c.Options.DeviceOnlineMinTraffic > 0 {
			nocountUID = make(map[int]struct{})
			minTraffic := int64(c.Options.DeviceOnlineMinTraffic * 1000)
			for _, traffic := range userTraffic {
				if traffic.Upload+traffic.Download < minTraffic {
					nocountUID[traffic.UID] = struct{}{}
				}
			}
		}
		aliveData = make(map[int][]string, len(onlineDevice))
		for _, online := range onlineDevice {
			if nocountUID != nil {
				if _, ok := nocountUID[online.UID]; ok {
					continue
				}
			}
			aliveData[online.UID] = append(aliveData[online.UID], online.IP)
		}
	}

	// 面板以 /report 刷新节点心跳，无流量无在线时也要发空包，否则空闲节点 5 分钟后显示离线
	c.sendDeviceReport(aliveData)

	reportErr := c.apiClient.Report(ctx, userTraffic, aliveData)
	if reportErr != nil {
		entry := log.WithFields(log.Fields{
			"tag": c.tag,
			"err": reportErr,
		})
		switch {
		case panel.IsNotDelivered(reportErr):
			c.pendingTraffic = userTraffic
			entry.Warn("V2 report not delivered, traffic kept for next report")
		case errors.Is(reportErr, context.Canceled), errors.Is(reportErr, context.DeadlineExceeded):
			entry.Info("V2 report cancelled, traffic discarded")
		case panel.IsUnsupportedReportError(reportErr):
			entry.Info("V2 report unsupported, fallback to V1")
			c.reportV1(userTraffic, aliveData, onlineDeviceCount)
		default:
			// 面板可能已入账（超时、连接中途断开），重发会重复计费
			entry.Warn("V2 report failed, traffic discarded")
		}
		return nil
	}
	if len(userTraffic) > 0 {
		var totalUp, totalDown int64
		for i := range userTraffic {
			totalUp += userTraffic[i].Upload
			totalDown += userTraffic[i].Download
		}
		log.WithField("tag", c.tag).Infof("Report %d users traffic (up=%d down=%d total=%.2f MB)",
			len(userTraffic), totalUp, totalDown, float64(totalUp+totalDown)/1024.0/1024.0)
	}
	if onlineDeviceCount > 0 {
		log.WithField("tag", c.tag).Infof("Total %d online users, %d Reported", onlineDeviceCount, len(aliveData))
	}
	return nil
}

func (c *Controller) reportV1(userTraffic []panel.UserTraffic, aliveData map[int][]string, onlineDeviceCount int) {
	ctx := c.currentCtx()
	if len(userTraffic) > 0 {
		err := c.apiClient.ReportUserTraffic(ctx, userTraffic)
		if err != nil {
			entry := log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			})
			switch {
			case panel.IsNotDelivered(err):
				c.pendingTraffic = userTraffic
				entry.Warn("V1 report not delivered, traffic kept for next report")
			case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
				entry.Info("V1 report cancelled, traffic discarded")
			default:
				entry.Info("Report user traffic failed")
			}
		} else {
			var totalUp, totalDown int64
			for i := range userTraffic {
				totalUp += userTraffic[i].Upload
				totalDown += userTraffic[i].Download
			}
			log.WithField("tag", c.tag).Infof("Report %d users traffic (up=%d down=%d total=%.2f MB)",
				len(userTraffic), totalUp, totalDown, float64(totalUp+totalDown)/1024.0/1024.0)
		}
	}
	if len(aliveData) > 0 {
		if err := c.apiClient.ReportNodeOnlineUsers(ctx, &aliveData); err != nil {
			entry := log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			})
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				entry.Info("Report online users cancelled")
			} else {
				entry.Info("Report online users failed")
			}
		} else {
			log.WithField("tag", c.tag).Infof("Total %d online users, %d Reported", onlineDeviceCount, len(aliveData))
		}
	}
}

// mergeTraffic 按 UID 合并两批流量；结果数量受用户数约束，积压再久也不会无限增长
func mergeTraffic(a, b []panel.UserTraffic) []panel.UserTraffic {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	idx := make(map[int]int, len(a)+len(b))
	out := make([]panel.UserTraffic, 0, len(a)+len(b))
	for _, list := range [][]panel.UserTraffic{a, b} {
		for _, t := range list {
			if i, ok := idx[t.UID]; ok {
				out[i].Upload += t.Upload
				out[i].Download += t.Download
				continue
			}
			idx[t.UID] = len(out)
			out = append(out, t)
		}
	}
	return out
}

// stashTraffic 在删除入站前取走未上报的流量，留给下次上报，避免重载丢流量。须持有 runtimeMu
func (c *Controller) stashTraffic() {
	t, err := c.server.GetUserTrafficSlice(c.tag, true)
	if err != nil {
		log.WithFields(log.Fields{"tag": c.tag, "err": err}).Warn("Stash user traffic failed")
		return
	}
	c.pendingTraffic = mergeTraffic(c.pendingTraffic, t)
}

// flushTraffic 关闭节点时把未上报的流量补报一次
func (c *Controller) flushTraffic() {
	c.runtimeMu.Lock()
	defer c.runtimeMu.Unlock()
	c.stashTraffic()
	if len(c.pendingTraffic) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := c.apiClient.Report(ctx, c.pendingTraffic, nil)
	if panel.IsUnsupportedReportError(err) {
		err = c.apiClient.ReportUserTraffic(ctx, c.pendingTraffic)
	}
	entry := log.WithFields(log.Fields{"tag": c.tag, "users": len(c.pendingTraffic)})
	if err != nil {
		entry.WithField("err", err).Warn("Flush user traffic on close failed")
		return
	}
	c.pendingTraffic = nil
	entry.Info("Flushed user traffic on close")
}

func (c *Controller) rebuildUIDToUUID() {
	m := make(map[int]string, len(c.userList))
	for i := range c.userList {
		m[c.userList[i].Id] = c.userList[i].Uuid
	}
	c.uidToUUID = m
}

func (c *Controller) addDynamicTraffic(userTraffic []panel.UserTraffic) {
	if !c.LimitConfig.EnableDynamicSpeedLimit || c.LimitConfig.DynamicSpeedLimitConfig == nil {
		return
	}
	if len(userTraffic) == 0 {
		return
	}
	if c.traffic == nil {
		c.traffic = make(map[string]int64)
	}
	if len(c.traffic) == 0 && c.info != nil && c.info.PushInterval > 0 {
		// 空窗口（含节点空闲期）从本次上报覆盖的区间起算，避免均速被稀释
		c.trafficSince = time.Now().Add(-c.info.PushInterval)
	}
	for i := range userTraffic {
		uuid, ok := c.uidToUUID[userTraffic[i].UID]
		if !ok {
			continue
		}
		c.traffic[uuid] += userTraffic[i].Upload + userTraffic[i].Download
	}
	c.checkDynamicSpeed()
}

// compareUserList 只有限速/设备数变化的用户归入 updated：内核用户与 uuid 绑定，不必删了重加
// （删用户会丢掉未上报的流量计数并断开全部连接）
func compareUserList(old, new []panel.UserInfo) (deleted, added, updated []panel.UserInfo) {
	oldMap := make(map[string]int, len(old))
	for i, user := range old {
		oldMap[user.Uuid] = i
	}

	for _, user := range new {
		i, exists := oldMap[user.Uuid]
		if !exists {
			added = append(added, user)
			continue
		}
		delete(oldMap, user.Uuid)
		prev := old[i]
		switch {
		case prev.Id != user.Id:
			deleted = append(deleted, prev)
			added = append(added, user)
		case prev.SpeedLimit != user.SpeedLimit || prev.DeviceLimit != user.DeviceLimit || prev.ConnLimit != user.ConnLimit:
			updated = append(updated, user)
		}
	}

	for _, index := range oldMap {
		deleted = append(deleted, old[index])
	}

	return deleted, added, updated
}
