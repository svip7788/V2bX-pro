package conf

import (
	"encoding/json"
	"strings"
)

type CoreConfig struct {
	Type       string      `json:"Type"`
	Name       string      `json:"Name"`
	XrayConfig *XrayConfig `json:"-"`
}

type _CoreConfig CoreConfig

func (c *CoreConfig) UnmarshalJSON(b []byte) error {
	err := json.Unmarshal(b, (*_CoreConfig)(c))
	if err != nil {
		return err
	}
	if c.Type == "xray" {
		c.XrayConfig = NewXrayConfig()
		return json.Unmarshal(b, c.XrayConfig)
	}
	return nil
}

// dropLegacyCores 去掉已移除的 sing 内核；去掉后没有内核时补一个默认 xray。
// 节点 CoreName 指向被去掉的内核时清空，改由协议自动选择
func (p *Conf) dropLegacyCores() {
	if len(p.CoresConfig) == 0 {
		return
	}
	removed := make(map[string]struct{})
	kept := p.CoresConfig[:0]
	for _, c := range p.CoresConfig {
		if strings.EqualFold(c.Type, legacySingCore) {
			if c.Name != "" {
				removed[c.Name] = struct{}{}
			}
			continue
		}
		kept = append(kept, c)
	}
	p.CoresConfig = kept
	if len(kept) == 0 {
		p.CoresConfig = []CoreConfig{{Type: "xray", XrayConfig: NewXrayConfig()}}
	}
	for i := range p.NodeConfig {
		if _, ok := removed[p.NodeConfig[i].Options.CoreName]; ok {
			p.NodeConfig[i].Options.CoreName = ""
		}
	}
}
