package limiter

import (
	"strconv"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/relay"
)

type egressTable struct {
	users  map[int]string // 面板用户 ID -> 出口出站 tag，空串表示分了出口但不可用
	strict bool
}

// SetUserEgress 面板用户 ID → 出口出站 tag；引用本机已有出站的直接用其 tag
func (l *Limiter) SetUserEgress(nodeTag string, e *panel.UserEgress) {
	if e == nil || (len(e.Users) == 0 && !e.Strict) {
		l.egressUsers.Store(nil)
		return
	}
	tags := make(map[int]string, len(e.Outbounds))
	for _, o := range e.Outbounds {
		out, err := relay.ParseOutbound(o.Outbound)
		if err != nil {
			tags[o.Id] = ""
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
		users[n] = tags[id]
	}
	l.egressUsers.Store(&egressTable{users: users, strict: e.Strict})
}

// MatchEgress 返回用户（taguuid）指定的出口出站 tag；matched 为 false 走原路由，
// matched 为 true 而 tag 为空表示出口不可用或严格模式下没分到出口，须拒绝
func (l *Limiter) MatchEgress(taguuid string) (tag string, matched bool) {
	t := l.egressUsers.Load()
	if t == nil {
		return "", false
	}
	if v, ok := l.userLimitInfo.Load(taguuid); ok {
		if tag, ok = t.users[v.(*UserLimitInfo).UID]; ok {
			return tag, true
		}
	}
	return "", t.strict
}
