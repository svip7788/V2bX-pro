package dispatcher

import (
	"strconv"
	"strings"

	"github.com/InazumaV/V2bX/common/sshguard"
	"github.com/InazumaV/V2bX/limiter"
	llog "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

// sshRejected 用户被识别为 SSH 爆破/扫描时拒绝其 22 端口连接
func sshRejected(in *session.Inbound, l *limiter.Limiter, dest net.Destination, host string) bool {
	if dest.Network != net.Network_TCP || dest.Port != sshguard.Port || in.User == nil {
		return false
	}
	key := in.User.Email
	if _, uuid, ok := strings.Cut(key, "|"); ok {
		if uid, ok := l.GetUIDByUUID(uuid); ok {
			key = strconv.Itoa(uid)
		}
	}
	r := sshguard.Check(key, host)
	if r.NewBan {
		llog.WithFields(llog.Fields{
			"user":   in.User.Email,
			"dest":   host,
			"reason": r.Reason,
			"until":  r.Until.Format("01-02 15:04"),
		}).Warn("SSH brute force detected, port 22 blocked for user")
	}
	return r.Reject
}
