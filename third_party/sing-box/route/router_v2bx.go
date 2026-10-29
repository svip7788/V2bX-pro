package route

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
)

func (r *Router) GetCtx() context.Context {
	return r.ctx
}

// SetOutboundOverride 须在 Start 前调用；f 返回非空 tag 时替换规则选出的出站
func (r *Router) SetOutboundOverride(f func(metadata *adapter.InboundContext) string) {
	r.outboundOverride = f
}

func (r *Router) overrideOutbound(metadata *adapter.InboundContext, selected adapter.Outbound, network string) adapter.Outbound {
	if r.outboundOverride == nil || selected == nil || selected.Type() == C.TypeBlock {
		return selected
	}
	tag := r.outboundOverride(metadata)
	if tag == "" {
		return selected
	}
	o, loaded := r.outbound.Outbound(tag)
	if !loaded {
		r.logger.Warn("relay outbound not found: ", tag)
		return selected
	}
	if !common.Contains(o.Network(), network) {
		return selected
	}
	r.logger.Debug("relay [", tag, "] for ", metadata.Destination)
	return o
}
