package node

import (
	"fmt"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	log "github.com/sirupsen/logrus"
)

type Node struct {
	controllers []*Controller
}

func New() *Node {
	return &Node{}
}

func (n *Node) Start(nodes []conf.NodeConfig, core vCore.Core) error {
	n.controllers = make([]*Controller, len(nodes))
	skipped := 0
	for i := range nodes {
		p, err := panel.New(&nodes[i].ApiConfig)
		if err != nil {
			n.Close()
			return err
		}
		c := NewController(core, p, &nodes[i].Options)
		err = c.Start()
		// 配置里残留已删除的节点时不能拖垮同进程的其它节点
		if err != nil && panel.IsNodeNotExist(err) {
			c.cancel()
			skipped++
			log.WithFields(log.Fields{
				"node_type": nodes[i].ApiConfig.NodeType,
				"node_id":   nodes[i].ApiConfig.NodeID,
			}).Error("Node does not exist on panel, skipped; remove it from config")
			continue
		}
		n.controllers[i] = c
		if err != nil {
			n.Close()
			return fmt.Errorf("start node controller [%s-%s-%d] error: %s",
				nodes[i].ApiConfig.APIHost,
				nodes[i].ApiConfig.NodeType,
				nodes[i].ApiConfig.NodeID,
				err)
		}
	}
	if skipped > 0 && skipped == len(nodes) {
		n.Close()
		return fmt.Errorf("all %d nodes do not exist on panel", skipped)
	}
	return nil
}

func (n *Node) Close() {
	for _, c := range n.controllers {
		if c == nil {
			continue
		}
		if err := c.Close(); err != nil {
			log.WithField("err", err).Error("Close controller failed")
		}
	}
	n.controllers = nil
}
