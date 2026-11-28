package xray

import (
	"context"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/relay"
	log "github.com/sirupsen/logrus"
)

func egressOwner(nodeTag string) string {
	return nodeTag + "|egress"
}

// UpdateUserEgress 增量同步节点的按用户出口：只增删有变化的出站，不重建入站、不影响其他连接
func (c *Xray) UpdateUserEgress(nodeTag string, e *panel.UserEgress) {
	want := map[string]string{}
	if e != nil {
		for _, o := range e.Outbounds {
			want[relay.EgressTag(nodeTag, o.Id)] = o.Outbound
		}
	}
	c.egressMu.Lock()
	defer c.egressMu.Unlock()
	cur := c.egress[nodeTag]
	for tag, v := range cur {
		if want[tag] != v {
			_ = c.ohm.RemoveHandler(context.Background(), tag)
		}
	}
	next := make(map[string]string, len(want))
	var outs []*relay.Outbound
	for tag, v := range want {
		o, err := relay.ParseOutbound(v)
		if err != nil {
			log.WithFields(log.Fields{"tag": tag, "err": err}).Error("Parse egress outbound failed")
			continue
		}
		if o.Ref != "" {
			continue
		}
		if cur[tag] != v {
			cfg, err := buildRelayOutbound(tag, o)
			if err == nil {
				_ = c.ohm.RemoveHandler(context.Background(), tag)
				err = c.addOutbound(cfg)
			}
			if err != nil {
				log.WithFields(log.Fields{"tag": tag, "err": err}).Error("Add egress outbound failed")
				continue
			}
		}
		next[tag] = v
		outs = append(outs, o)
	}
	if len(next) == 0 {
		delete(c.egress, nodeTag)
	} else {
		c.egress[nodeTag] = next
	}
	relay.AllowEgress(egressOwner(nodeTag), outs)
}
