package limiter

import (
	"strconv"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/relay"
)

// SetUserEgress 面板用户 ID → 出口出站 tag；引用本机已有出站的直接用其 tag
func (l *Limiter) SetUserEgress(nodeTag string, e *panel.UserEgress) {
	if e == nil || len(e.Users) == 0 {
		l.egressUsers.Store(nil)
		return
	}
	tags := make(map[int]string, len(e.Outbounds))
	for _, o := range e.Outbounds {
		out, err := relay.ParseOutbound(o.Outbound)
		if err != nil {
			continue
		}
		if out.Ref != "" {
			tags[o.Id] = out.Ref
		} else {
			tags[o.Id] = relay.EgressTag(nodeTag, o.Id)
		}
	}
	users := make(map[int]string, len(e.Users))
	for uid, id := range e.Users {
		n, err := strconv.Atoi(uid)
		if err != nil {
			continue
		}
		if tag, ok := tags[id]; ok {
			users[n] = tag
		}
	}
	l.egressUsers.Store(&users)
}

// MatchEgress 返回用户（taguuid）指定的出口出站 tag，空串表示走默认出站
func (l *Limiter) MatchEgress(taguuid string) string {
	m := l.egressUsers.Load()
	if m == nil {
		return ""
	}
	v, ok := l.userLimitInfo.Load(taguuid)
	if !ok {
		return ""
	}
	return (*m)[v.(*UserLimitInfo).UID]
}
