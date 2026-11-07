package sing

import (
	"fmt"
	"strconv"

	"github.com/InazumaV/V2bX/common/ipwatch"
	"github.com/InazumaV/V2bX/common/violation"
	"github.com/InazumaV/V2bX/limiter"
	"github.com/sagernet/sing-box/adapter"
	llog "github.com/sirupsen/logrus"
)

// watchIPQuery 用户频繁访问查询出口 IP 的目标时上报面板记录，不拦截
func watchIPQuery(l *limiter.Limiter, m adapter.InboundContext, host string) {
	if !ipwatch.Enabled(m.Inbound) {
		return
	}
	uid, ok := l.GetUIDByUUID(m.User)
	if !ok {
		return
	}
	target, n := ipwatch.Check(m.Inbound, strconv.Itoa(uid), host, m.Domain)
	if n == 0 {
		return
	}
	llog.WithFields(llog.Fields{"tag": m.Inbound, "user": m.User, "dest": target, "count": n}).Warn("Frequent IP query detected")
	reportViolation(l, m, violation.KindIPQuery, target, fmt.Sprintf("10 分钟内访问 IP 查询目标 %d 次", n))
}
