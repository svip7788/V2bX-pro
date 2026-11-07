package dispatcher

import (
	"fmt"
	"strconv"

	"github.com/InazumaV/V2bX/common/ipwatch"
	"github.com/InazumaV/V2bX/common/violation"
	"github.com/InazumaV/V2bX/limiter"
	llog "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/session"
)

// watchIPQuery 用户频繁访问查询出口 IP 的目标时上报面板记录，不拦截
func watchIPQuery(in *session.Inbound, l *limiter.Limiter, ob *session.Outbound, host string) {
	if !ipwatch.Enabled(in.Tag) {
		return
	}
	uid := userUID(in, l)
	if uid <= 0 {
		return
	}
	hosts := []string{host}
	if ob != nil && ob.RouteTarget.Address != nil && ob.RouteTarget.Address.Family().IsDomain() {
		hosts = append(hosts, ob.RouteTarget.Address.Domain())
	}
	target, n := ipwatch.Check(in.Tag, strconv.Itoa(uid), hosts...)
	if n == 0 {
		return
	}
	llog.WithFields(llog.Fields{"user": in.User.Email, "dest": target, "count": n}).Warn("Frequent IP query detected")
	reportViolation(in, l, violation.KindIPQuery, target, fmt.Sprintf("10 分钟内访问 IP 查询目标 %d 次", n))
}
