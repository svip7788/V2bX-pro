package sing

import (
	"context"
	"fmt"
	"strings"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/relay"
	"github.com/InazumaV/V2bX/limiter"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/json"
	llog "github.com/sirupsen/logrus"
)

// relayOutboundTag 面板 proxy 路由组命中时返回转发出站 tag；
// 未转发的 TCP 连接若域名命中 dns 路由组，就地把目标改为指定上游解析出的 IP
func relayOutboundTag(m *adapter.InboundContext) string {
	if m.User == "" {
		return ""
	}
	l, err := limiter.GetLimiter(m.Inbound)
	if err != nil {
		return ""
	}
	host := m.Domain
	if host == "" {
		host = m.Destination.Fqdn
	}
	if tag := l.MatchRelay(m.Inbound, host, m.Destination.Addr, m.Destination.Port); tag != "" {
		return tag
	}
	if m.Network == N.NetworkTCP {
		resolveDestination(l, m, host)
	}
	return ""
}

func resolveDestination(l *limiter.Limiter, m *adapter.InboundContext, host string) {
	r := l.MatchDNS(host)
	if r == nil {
		return
	}
	ip, err := r.Lookup(context.Background(), host)
	if err != nil {
		llog.WithFields(llog.Fields{"dns": r.String(), "host": host, "err": err}).Debug("dns rule resolve failed")
		return
	}
	m.Destination = M.SocksaddrFrom(ip, m.Destination.Port)
}

func (b *Sing) buildRelayOutbound(o *relay.Outbound) (string, any, error) {
	if o.Raw != nil {
		out, err := json.UnmarshalExtendedContext[option.Outbound](b.ctx, o.Raw)
		if err != nil {
			return "", nil, err
		}
		if out.Type == "" {
			return "", nil, fmt.Errorf("outbound json missing type (sing-box format)")
		}
		return out.Type, out.Options, nil
	}
	server := option.ServerOptions{Server: o.Server, ServerPort: o.Port}
	switch o.Type {
	case relay.TypeShadowsocks:
		return C.TypeShadowsocks, &option.ShadowsocksOutboundOptions{
			ServerOptions: server,
			Method:        o.Method,
			Password:      o.Password,
		}, nil
	case relay.TypeSocks:
		return C.TypeSOCKS, &option.SOCKSOutboundOptions{
			ServerOptions: server,
			Version:       "5",
			Username:      o.Username,
			Password:      o.Password,
		}, nil
	case relay.TypeHTTP:
		return C.TypeHTTP, &option.HTTPOutboundOptions{
			ServerOptions: server,
			Username:      o.Username,
			Password:      o.Password,
		}, nil
	}
	return "", nil, fmt.Errorf("unsupported outbound type %q", o.Type)
}

// addRelayOutbounds 单条转发出站失败不影响节点上线，命中时回落到原路由
func (b *Sing) addRelayOutbounds(nodeTag string, rules []panel.RelayRule) {
	for _, r := range rules {
		o, err := relay.ParseOutbound(r.Outbound)
		if err != nil {
			llog.WithFields(llog.Fields{"tag": nodeTag, "route": r.Id, "err": err}).Error("Parse relay outbound failed")
			continue
		}
		if o.Ref != "" {
			continue
		}
		typ, opts, err := b.buildRelayOutbound(o)
		if err == nil {
			tag := relay.Tag(nodeTag, r.Id)
			err = b.box.Outbound().Create(b.ctx, b.router, b.logFactory.NewLogger(F.ToString("outbound/", typ, "[", tag, "]")), tag, typ, opts)
		}
		if err != nil {
			llog.WithFields(llog.Fields{"tag": nodeTag, "route": r.Id, "err": err}).Error("Add relay outbound failed")
		}
	}
}

func (b *Sing) removeRelayOutbounds(nodeTag string) {
	prefix := relay.TagPrefix(nodeTag)
	for _, o := range b.box.Outbound().Outbounds() {
		if strings.HasPrefix(o.Tag(), prefix) {
			_ = b.box.Outbound().Remove(o.Tag())
		}
	}
}
