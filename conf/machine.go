package conf

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const MachineAssetDir = "/etc/V2bX/"

// MachineConfig 机器模式：整台机器以 machine_id + token 连接 Xboard，节点列表由面板下发
type MachineConfig struct {
	APIHost   string `json:"ApiHost"`
	APISendIP string `json:"ApiSendIP,omitempty"`
	MachineID int    `json:"MachineID"`
	Token     string `json:"Token"`
	// 已废弃：内核固定为 xray，保留字段以兼容旧配置
	Core    string `json:"Core,omitempty"`
	Timeout int    `json:"Timeout,omitempty"`
	// 覆盖每个节点的默认 Options，字段与 Nodes 单项相同
	NodeDefaults json.RawMessage `json:"NodeDefaults,omitempty"`

	// 多站时区分各面板的自签证书文件，避免同号节点互相覆盖
	certPrefix string
}

func (m *MachineConfig) Enabled() bool {
	return m != nil && m.MachineID > 0
}

func (m *MachineConfig) panelKey() string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(m.APIHost), "/"))
}

func (m *MachineConfig) panelSlug() string {
	host := m.panelKey()
	if u, err := url.Parse(host); err == nil && u.Host != "" {
		host = u.Host
	}
	var b strings.Builder
	for _, r := range host {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// 必须带 TLS 证书的协议，未配置证书时用自签
var selfCertTypes = map[string]struct{}{
	"hysteria2": {},
	"tuic":      {},
	"anytls":    {},
}

// hysteria v1 不在列表中：xray 只支持 Hysteria2，面板下发的 v1 节点会被跳过
var machineNodeTypes = map[string]struct{}{
	"vmess":       {},
	"vless":       {},
	"trojan":      {},
	"shadowsocks": {},
	"hysteria2":   {},
	"tuic":        {},
	"anytls":      {},
}

// NormalizeMachineNodeType 返回 V2bX 支持的节点类型，不支持时返回空串
func NormalizeMachineNodeType(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	if t == "v2ray" {
		t = "vmess"
	}
	if _, ok := machineNodeTypes[t]; !ok {
		return ""
	}
	return t
}

// MachineCoreConfigs 已手写 Cores 时原样使用，否则生成默认 xray 内核配置；多站共用同一个内核
func MachineCoreConfigs(existing []CoreConfig) []CoreConfig {
	if len(existing) > 0 {
		return existing
	}
	return []CoreConfig{{Type: "xray", XrayConfig: defaultMachineXrayConfig()}}
}

func defaultMachineXrayConfig() *XrayConfig {
	x := NewXrayConfig()
	x.AssetPath = MachineAssetDir
	x.LogConfig.Level = "error"
	// 留空时 xray 会把每条连接的 access 日志写到 stdout，高并发下 journald 写盘明显吃 CPU
	x.LogConfig.AccessPath = "none"
	x.LogConfig.ErrorPath = ""
	// dns/route/outbound 由 resolveOptionalConfigPath 在文件存在时自动使用
	if p := machineAsset("custom_inbound.json"); p != "" {
		x.InboundConfigPath = p
	}
	return x
}

func machineAsset(name string) string {
	p := filepath.Join(MachineAssetDir, name)
	info, err := os.Stat(p)
	if err != nil || info.IsDir() || info.Size() == 0 {
		return ""
	}
	return p
}

// NodeConfig 生成单个面板节点的运行配置
func (m *MachineConfig) NodeConfig(nodeID int, nodeType string) (NodeConfig, error) {
	timeout := m.Timeout
	if timeout <= 0 {
		timeout = 30
	}
	nc := NodeConfig{
		ApiConfig: ApiConfig{
			APIHost:   strings.TrimRight(m.APIHost, "/"),
			APISendIP: m.APISendIP,
			Key:       m.Token,
			NodeType:  nodeType,
			Timeout:   timeout,
		},
	}
	nc.ApiConfig.SetNodeIDs([]int{nodeID})

	opts, err := m.nodeOptionsJSON(nodeID, nodeType)
	if err != nil {
		return NodeConfig{}, err
	}
	nc.Options = Options{
		ListenIP:   "0.0.0.0",
		SendIP:     "0.0.0.0",
		CertConfig: NewCertConfig(),
	}
	if err := json.Unmarshal(opts, &nc.Options); err != nil {
		return NodeConfig{}, fmt.Errorf("unmarshal node %d options error: %w", nodeID, err)
	}
	return nc, nil
}

func (m *MachineConfig) nodeOptionsJSON(nodeID int, nodeType string) ([]byte, error) {
	_, needCert := selfCertTypes[nodeType]
	certMode := "none"
	if needCert {
		certMode = "self"
	}
	opts := map[string]any{
		"Core":                   "xray",
		"ListenIP":               "0.0.0.0",
		"SendIP":                 "0.0.0.0",
		"DeviceOnlineMinTraffic": 200,
		"CertConfig": map[string]any{
			"CertMode":   certMode,
			"CertDomain": "",
			"CertFile":   fmt.Sprintf("%scert/%snode%d.crt", MachineAssetDir, m.certPrefix, nodeID),
			"KeyFile":    fmt.Sprintf("%scert/%snode%d.key", MachineAssetDir, m.certPrefix, nodeID),
		},
	}
	if len(m.NodeDefaults) > 0 {
		var overrides map[string]any
		if err := json.Unmarshal(m.NodeDefaults, &overrides); err != nil {
			return nil, fmt.Errorf("unmarshal Machine.NodeDefaults error: %w", err)
		}
		for k, v := range overrides {
			if k == "CertConfig" {
				if base, ok := opts["CertConfig"].(map[string]any); ok {
					if over, ok := v.(map[string]any); ok {
						for ck, cv := range over {
							base[ck] = cv
						}
						continue
					}
				}
			}
			opts[k] = v
		}
		opts["Core"] = "xray"
	}
	return json.Marshal(opts)
}
