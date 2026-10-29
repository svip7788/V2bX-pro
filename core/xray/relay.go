package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/relay"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func buildRelayOutbound(tag string, o *relay.Outbound) (*core.OutboundHandlerConfig, error) {
	var detour coreConf.OutboundDetourConfig
	if o.Raw != nil {
		if err := json.Unmarshal(o.Raw, &detour); err != nil {
			return nil, err
		}
		if detour.Protocol == "" {
			return nil, fmt.Errorf("outbound json missing protocol (xray format)")
		}
	} else {
		settings := map[string]any{"address": o.Server, "port": o.Port}
		switch o.Type {
		case relay.TypeShadowsocks:
			settings["method"] = o.Method
			settings["password"] = o.Password
		case relay.TypeSocks, relay.TypeHTTP:
			if o.Username != "" {
				settings["user"] = o.Username
				settings["pass"] = o.Password
			}
		}
		raw, err := json.Marshal(settings)
		if err != nil {
			return nil, err
		}
		msg := json.RawMessage(raw)
		detour.Protocol = o.Type
		detour.Settings = &msg
	}
	detour.Tag = tag
	return detour.Build()
}

// addRelayOutbounds 单条转发出站失败不影响节点上线，命中时回落到原路由
func (c *Xray) addRelayOutbounds(nodeTag string, rules []panel.RelayRule) {
	// 重载失败重试时可能残留同名出站，xray 不允许重复 tag
	c.removeRelayOutbounds(nodeTag)
	for _, r := range rules {
		o, err := relay.ParseOutbound(r.Outbound)
		if err != nil {
			log.WithFields(log.Fields{"tag": nodeTag, "route": r.Id, "err": err}).Error("Parse relay outbound failed")
			continue
		}
		if o.Ref != "" {
			continue
		}
		cfg, err := buildRelayOutbound(relay.Tag(nodeTag, r.Id), o)
		if err == nil {
			err = c.addOutbound(cfg)
		}
		if err != nil {
			log.WithFields(log.Fields{"tag": nodeTag, "route": r.Id, "err": err}).Error("Add relay outbound failed")
		}
	}
}

func (c *Xray) removeRelayOutbounds(nodeTag string) {
	prefix := relay.TagPrefix(nodeTag)
	for _, h := range c.ohm.ListHandlers(context.Background()) {
		if strings.HasPrefix(h.Tag(), prefix) {
			_ = c.ohm.RemoveHandler(context.Background(), h.Tag())
		}
	}
}
