package xray

import (
	"context"
	"fmt"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	"github.com/InazumaV/V2bX/core/xray/app/dispatcher"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
)

type DNSConfig struct {
	Servers []interface{} `json:"servers"`
	Tag     string        `json:"tag"`
}

func (c *Xray) AddNode(tag string, info *panel.NodeInfo, config *conf.Options) error {
	err := updateDNSConfig(info)
	if err != nil {
		return fmt.Errorf("build dns error: %s", err)
	}
	inboundConfig, err := buildInbound(config, info, tag)
	if err != nil {
		return fmt.Errorf("build inbound error: %s", err)
	}
	outBoundConfig, err := buildOutbound(config, tag)
	if err != nil {
		return fmt.Errorf("build outbound error: %s", err)
	}
	err = c.addInbound(inboundConfig)
	if err != nil {
		return fmt.Errorf("add inbound error: %s", err)
	}
	err = c.addOutbound(outBoundConfig)
	if err != nil {
		_ = c.removeInbound(tag)
		return fmt.Errorf("add outbound error: %s", err)
	}
	c.addRelayOutbounds(tag, info.Rules.Relay)
	c.users.mapLock.Lock()
	c.nodeReportMinTrafficBytes[tag] = config.ReportMinTraffic * 1024
	c.users.mapLock.Unlock()
	return nil
}

func (c *Xray) addInbound(config *core.InboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(c.Server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(inbound.Handler)
	if !ok {
		return fmt.Errorf("not an InboundHandler: %s", err)
	}
	if err := c.ihm.AddHandler(context.Background(), handler); err != nil {
		// xray 先登记 tag 再监听端口：监听失败（端口占用等）时 handler 仍留在表里，
		// 不移除的话之后同 tag 永远报 existing tag found
		if h, gerr := c.ihm.GetHandler(context.Background(), handler.Tag()); gerr == nil && h == handler {
			_ = c.ihm.RemoveHandler(context.Background(), handler.Tag())
		}
		return err
	}
	return nil
}

func (c *Xray) addOutbound(config *core.OutboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(c.Server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(outbound.Handler)
	if !ok {
		return fmt.Errorf("not an OutboundHandler: %s", err)
	}
	if err := c.ohm.AddHandler(context.Background(), handler); err != nil {
		return err
	}
	return nil
}

func (c *Xray) DelNode(tag string) error {
	err := c.removeInbound(tag)
	if err != nil {
		return fmt.Errorf("remove in error: %s", err)
	}
	err = c.removeOutbound(tag)
	c.removeRelayOutbounds(tag)
	c.dispatcher.Counter.Delete(tag)
	prefix := tag + "|"
	c.dispatcher.LinkManagers.Range(func(key, value interface{}) bool {
		if email, ok := key.(string); ok && len(email) > len(prefix) && email[:len(prefix)] == prefix {
			lm := value.(*dispatcher.LinkManager)
			lm.CloseAll()
			c.dispatcher.LinkManagers.Delete(key)
		}
		return true
	})
	c.users.mapLock.Lock()
	for k := range c.users.uidMap {
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			delete(c.users.uidMap, k)
		}
	}
	delete(c.nodeReportMinTrafficBytes, tag)
	c.users.mapLock.Unlock()
	if err != nil {
		return fmt.Errorf("remove out error: %s", err)
	}
	return nil
}

func (c *Xray) removeInbound(tag string) error {
	return c.ihm.RemoveHandler(context.Background(), tag)
}

func (c *Xray) removeOutbound(tag string) error {
	err := c.ohm.RemoveHandler(context.Background(), tag)
	return err
}
