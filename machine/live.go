package machine

import (
	"encoding/json"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/livelog"
)

// handleLive 后台「实时连接」：watch 开始/续约，stop 结束；在 WS 读协程里调用，不能阻塞
func (m *Manager) handleLive(evt panel.WSEvent) bool {
	switch evt.Event {
	case "machine.live.watch", "machine.live.stop":
	default:
		return false
	}
	var msg struct {
		SID string `json:"sid"`
		UID int    `json:"uid"`
		TTL int    `json:"ttl"`
	}
	if err := json.Unmarshal(evt.Data, &msg); err != nil || msg.SID == "" {
		return true
	}
	if evt.Event == "machine.live.stop" {
		livelog.Stop(msg.SID)
		return true
	}
	livelog.Watch(msg.SID, "["+m.client.APIHost()+"]-", msg.UID, time.Duration(msg.TTL)*time.Second, m.send)
	return true
}
