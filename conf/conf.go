package conf

import (
	"fmt"
	"io"
	"os"
	"sync/atomic"

	"github.com/InazumaV/V2bX/common/json5"

	"encoding/json/v2"
)

type Conf struct {
	LogConfig   LogConfig    `json:"Log"`
	CoresConfig []CoreConfig `json:"Cores"`
	NodeConfig  []NodeConfig `json:"Nodes"`
	// 设置且 MachineID>0 时进入机器模式，忽略 Nodes
	MachineConfig *MachineConfig `json:"Machine"`
	// 同一台机器接入多个面板（多站），第一个站在 Machine，其余在此追加
	MachineConfigs []*MachineConfig `json:"Machines"`
	// 默认所有域名解析只走本机系统 DNS（/etc/resolv.conf，机房的解锁 DNS 配在这里），
	// dns.json 和面板下发的 dns 路由一律忽略；设为 true 才恢复自定义 DNS
	AllowCustomDNS bool `json:"AllowCustomDNS"`
}

var allowCustomDNS atomic.Bool

// CustomDNSAllowed 为 false 时只用本机系统 DNS
func CustomDNSAllowed() bool {
	return allowCustomDNS.Load()
}

func SetAllowCustomDNS(v bool) {
	allowCustomDNS.Store(v)
}

// Machines 返回所有启用的机器配置，同一面板地址只保留第一个
func (p *Conf) Machines() []*MachineConfig {
	var out []*MachineConfig
	seen := make(map[string]struct{})
	add := func(m *MachineConfig, extra bool) {
		if !m.Enabled() {
			return
		}
		key := m.panelKey()
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		if extra {
			m.certPrefix = m.panelSlug() + "-"
		}
		out = append(out, m)
	}
	add(p.MachineConfig, false)
	for _, m := range p.MachineConfigs {
		add(m, true)
	}
	return out
}

func New() *Conf {
	return &Conf{
		LogConfig: LogConfig{
			Level:  "warning",
			Output: "",
		},
	}
}

func (p *Conf) LoadFromPath(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open config file error: %s", err)
	}
	defer f.Close()

	reader := json5.NewTrimNodeReader(f)
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("read config file error: %s", err)
	}

	err = json.Unmarshal(data, p)
	if err != nil {
		return fmt.Errorf("unmarshal config error: %s", err)
	}
	p.dropLegacyCores()
	SetAllowCustomDNS(p.AllowCustomDNS)
	return nil
}
