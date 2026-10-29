package sing

import (
	"strings"

	"github.com/InazumaV/V2bX/common/counter"
	"github.com/InazumaV/V2bX/common/livelog"
	"github.com/InazumaV/V2bX/limiter"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

// liveOpen 用户正被后台实时查看时记录这条连接；未查看时只有一次原子读
func liveOpen(l *limiter.Limiter, m adapter.InboundContext, o adapter.Outbound) *livelog.Conn {
	if !livelog.Enabled() || m.User == "" {
		return nil
	}
	uid, ok := l.GetUIDByUUID(m.User)
	if !ok {
		return nil
	}
	host := m.Domain
	if host == "" {
		host = m.Destination.AddrString()
	}
	out := "direct"
	if o != nil {
		if o.Type() == C.TypeBlock {
			out = "block"
		} else if strings.Contains(o.Tag(), "|relay|") {
			out = "relay"
		}
	}
	return livelog.Open(m.Inbound, uid, m.Network, host, m.Destination.Port, m.Protocol, out)
}

func liveClose(c *livelog.Conn, s *counter.TrafficStorage) {
	c.AddUp(s.UpCounter.Load())
	c.AddDown(s.DownCounter.Load())
	c.Close()
}
