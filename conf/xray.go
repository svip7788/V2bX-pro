package conf

import (
	"os"
	"path/filepath"
)

type XrayConfig struct {
	LogConfig          *XrayLogConfig        `json:"Log"`
	AssetPath          string                `json:"AssetPath"`
	DnsConfigPath      string                `json:"DnsConfigPath"`
	RouteConfigPath    string                `json:"RouteConfigPath"`
	ConnectionConfig   *XrayConnectionConfig `json:"XrayConnectionConfig"`
	InboundConfigPath  string                `json:"InboundConfigPath"`
	OutboundConfigPath string                `json:"OutboundConfigPath"`
}

type XrayLogConfig struct {
	Level      string `json:"Level"`
	AccessPath string `json:"AccessPath"`
	ErrorPath  string `json:"ErrorPath"`
}

type XrayConnectionConfig struct {
	Handshake    uint32 `json:"handshake"`
	ConnIdle     uint32 `json:"connIdle"`
	UplinkOnly   uint32 `json:"uplinkOnly"`
	DownlinkOnly uint32 `json:"downlinkOnly"`
	BufferSize   int32  `json:"bufferSize"`
}

func NewXrayConfig() *XrayConfig {
	return &XrayConfig{
		LogConfig: &XrayLogConfig{
			Level:      "warning",
			AccessPath: "none",
			ErrorPath:  "",
		},
		AssetPath:          "/etc/V2bX/",
		DnsConfigPath:      "",
		InboundConfigPath:  "",
		OutboundConfigPath: "",
		RouteConfigPath:    "",
		ConnectionConfig: &XrayConnectionConfig{
			Handshake:    4,
			ConnIdle:     300,
			UplinkOnly:   2,
			DownlinkOnly: 4,
			BufferSize:   32,
		},
	}
}

type XrayOptions struct {
	EnableProxyProtocol bool                    `json:"EnableProxyProtocol"`
	EnableDNS           bool                    `json:"EnableDNS"`
	DNSType             string                  `json:"DNSType"`
	EnableUot           bool                    `json:"EnableUot"`
	EnableTFO           bool                    `json:"EnableTFO"`
	DisableIVCheck      bool                    `json:"DisableIVCheck"`
	DisableSniffing     bool                    `json:"DisableSniffing"`
	EnableFallback      bool                    `json:"EnableFallback"`
	FallBackConfigs     []FallBackConfigForXray `json:"FallBackConfigs"`
}

type FallBackConfigForXray struct {
	SNI              string `json:"SNI"`
	Alpn             string `json:"Alpn"`
	Path             string `json:"Path"`
	Dest             string `json:"Dest"`
	ProxyProtocolVer uint64 `json:"ProxyProtocolVer"`
}

func NewXrayOptions() *XrayOptions {
	return &XrayOptions{
		EnableProxyProtocol: false,
		EnableDNS:           true,
		DNSType:             "ForceIPv4",
		EnableUot:           false,
		EnableTFO:           false,
		DisableIVCheck:      false,
		DisableSniffing:     false,
		EnableFallback:      false,
	}
}

func (c *XrayConfig) ResolveDNSConfigPath() (string, bool) {
	return c.resolveOptionalConfigPath(c.DnsConfigPath, "dns.json")
}

func (c *XrayConfig) ResolveInboundConfigPath() (string, bool) {
	if c.InboundConfigPath == "" {
		return "", false
	}
	return c.InboundConfigPath, false
}

func (c *XrayConfig) ResolveRouteConfigPath() (string, bool) {
	return c.resolveOptionalConfigPath(c.RouteConfigPath, "route.json")
}

func (c *XrayConfig) ResolveOutboundConfigPath() (string, bool) {
	return c.resolveOptionalConfigPath(c.OutboundConfigPath, "custom_outbound.json")
}

func (c *XrayConfig) resolveOptionalConfigPath(configPath string, defaultName string) (string, bool) {
	if configPath != "" {
		return configPath, false
	}
	if c.AssetPath == "" {
		return "", false
	}
	candidate := filepath.Join(c.AssetPath, defaultName)
	info, err := os.Stat(candidate)
	if err != nil || info.IsDir() {
		return "", false
	}
	return candidate, true
}
