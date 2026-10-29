package dispatcher

import (
	"strconv"
	"strings"

	"github.com/InazumaV/V2bX/common/sshguard"
	"github.com/InazumaV/V2bX/common/violation"
	"github.com/InazumaV/V2bX/limiter"
	llog "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func userUID(in *session.Inbound, l *limiter.Limiter) int {
	if in.User == nil {
		return 0
	}
	if _, uuid, ok := strings.Cut(in.User.Email, "|"); ok {
		if uid, ok := l.GetUIDByUUID(uuid); ok {
			return uid
		}
	}
	return 0
}

// reportViolation 上报面板封号
func reportViolation(in *session.Inbound, l *limiter.Limiter, kind, target, detail string) {
	violation.Report(in.Tag, violation.Item{UID: userUID(in, l), Kind: kind, Target: target, Detail: detail})
}

// sshRejected 用户被识别为 SSH 爆破/扫描时拒绝其 22 端口连接并上报
func sshRejected(in *session.Inbound, l *limiter.Limiter, dest net.Destination, host string) bool {
	if dest.Network != net.Network_TCP || dest.Port != sshguard.Port || in.User == nil {
		return false
	}
	key := in.User.Email
	if uid := userUID(in, l); uid > 0 {
		key = strconv.Itoa(uid)
	}
	r := sshguard.Check(key, host)
	if r.NewBan {
		llog.WithFields(llog.Fields{
			"user":   in.User.Email,
			"dest":   host,
			"reason": r.Reason,
			"until":  r.Until.Format("01-02 15:04"),
		}).Warn("SSH brute force detected, port 22 blocked for user")
		reportViolation(in, l, violation.KindSSH, host+":22", r.Reason)
	}
	return r.Reject
}
