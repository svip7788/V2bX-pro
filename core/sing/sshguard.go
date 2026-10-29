package sing

import (
	"strconv"

	"github.com/InazumaV/V2bX/common/sshguard"
	"github.com/InazumaV/V2bX/limiter"
	"github.com/sagernet/sing-box/adapter"
	llog "github.com/sirupsen/logrus"
)

// sshRejected 用户被识别为 SSH 爆破/扫描时拒绝其 22 端口连接
func sshRejected(l *limiter.Limiter, m adapter.InboundContext, destStr string) bool {
	if m.Destination.Port != sshguard.Port {
		return false
	}
	host := m.Domain
	if host == "" {
		host = destStr
	}
	key := m.Inbound + "|" + m.User
	if uid, ok := l.GetUIDByUUID(m.User); ok {
		key = strconv.Itoa(uid)
	}
	r := sshguard.Check(key, host)
	if r.NewBan {
		llog.WithFields(llog.Fields{
			"tag":    m.Inbound,
			"user":   m.User,
			"dest":   host,
			"reason": r.Reason,
			"until":  r.Until.Format("01-02 15:04"),
		}).Warn("SSH brute force detected, port 22 blocked for user")
	}
	return r.Reject
}
