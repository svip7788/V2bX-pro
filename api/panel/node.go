package panel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"encoding/json"
)

// Security type
const (
	None    = 0
	Tls     = 1
	Reality = 2
)

type NodeInfo struct {
	Id           int
	Type         string
	Security     int
	PushInterval time.Duration
	PullInterval time.Duration
	RawDNS       RawDNS
	Rules        Rules
	CertConfig   *PanelCertConfig

	// origin
	VAllss      *VAllssNode
	Shadowsocks *ShadowsocksNode
	Trojan      *TrojanNode
	Tuic        *TuicNode
	AnyTls      *AnyTlsNode
	Hysteria    *HysteriaNode
	Hysteria2   *Hysteria2Node
	Common      *CommonNode
}

type PanelCertConfig struct {
	CertMode         string `json:"cert_mode"`
	CertFile         string `json:"cert_file"`
	KeyFile          string `json:"key_file"`
	CertDomain       string `json:"cert_domain"`
	Provider         string `json:"provider"`
	Email            string `json:"email"`
	RejectUnknownSni bool   `json:"reject_unknown_sni"`
}

type CommonNode struct {
	Host       string           `json:"host"`
	ServerPort int              `json:"server_port"`
	ServerName string           `json:"server_name"`
	Routes     []Route          `json:"routes"`
	BaseConfig *BaseConfig      `json:"base_config"`
	CertConfig *PanelCertConfig `json:"cert_config"`
}

type Route struct {
	Id          int         `json:"id"`
	Match       interface{} `json:"match"`
	Action      string      `json:"action"`
	ActionValue string      `json:"action_value"`
}
type BaseConfig struct {
	PushInterval any `json:"push_interval"`
	PullInterval any `json:"pull_interval"`
}

// VAllssNode is vmess and vless node info
type VAllssNode struct {
	CommonNode
	Tls                 int             `json:"tls"`
	TlsSettings         TlsSettings     `json:"tls_settings"`
	TlsSettingsBack     *TlsSettings    `json:"tlsSettings"`
	Network             string          `json:"network"`
	NetworkSettings     json.RawMessage `json:"network_settings"`
	NetworkSettingsBack json.RawMessage `json:"networkSettings"`
	Decryption          string          `json:"decryption"`
	Encryption          string          `json:"encryption"`
	EncryptionSettings  EncSettings     `json:"encryption_settings"`
	ServerName          string          `json:"server_name"`

	// vless only
	Flow          string        `json:"flow"`
	RealityConfig RealityConfig `json:"-"`
}

type TlsSettings struct {
	ServerName  string `json:"server_name"`
	Dest        string `json:"dest"`
	ServerPort  string `json:"server_port"`
	ShortId     string `json:"short_id"`
	PrivateKey  string `json:"private_key"`
	Mldsa65Seed string `json:"mldsa65Seed"`
	Xver        uint64 `json:"xver,string"`
}

type EncSettings struct {
	Mode          string `json:"mode"`
	Ticket        string `json:"ticket"`
	ServerPadding string `json:"server_padding"`
	PrivateKey    string `json:"private_key"`
}

type RealityConfig struct {
	Xver         uint64 `json:"Xver"`
	MinClientVer string `json:"MinClientVer"`
	MaxClientVer string `json:"MaxClientVer"`
	MaxTimeDiff  string `json:"MaxTimeDiff"`
}

type ShadowsocksNode struct {
	CommonNode
	Cipher          string          `json:"cipher"`
	ServerKey       string          `json:"server_key"`
	Plugin          string          `json:"plugin"`
	PluginOpts      string          `json:"plugin_opts"`
	NetworkSettings json.RawMessage `json:"networkSettings"`
}

type TrojanNode struct {
	CommonNode
	Tls             int             `json:"tls"`
	TlsSettings     TlsSettings     `json:"tls_settings"`
	Network         string          `json:"network"`
	NetworkSettings json.RawMessage `json:"networkSettings"`
}

type TuicNode struct {
	CommonNode
	CongestionControl string `json:"congestion_control"`
	ZeroRTTHandshake  bool   `json:"zero_rtt_handshake"`
}

type AnyTlsNode struct {
	CommonNode
	Network         string          `json:"network"`
	NetworkSettings json.RawMessage `json:"networkSettings"`
	PaddingScheme   []string        `json:"padding_scheme,omitempty"`
}

type HysteriaNode struct {
	CommonNode
	UpMbps   int    `json:"up_mbps"`
	DownMbps int    `json:"down_mbps"`
	Obfs     string `json:"obfs"`
}

type Hysteria2Node struct {
	CommonNode
	Ignore_Client_Bandwidth bool   `json:"ignore_client_bandwidth"`
	UpMbps                  int    `json:"up_mbps"`
	DownMbps                int    `json:"down_mbps"`
	ObfsType                string `json:"obfs"`
	ObfsPassword            string `json:"obfs-password"`
}

type RawDNS struct {
	DNSMap  map[string]map[string]interface{}
	DNSJson []byte
}

type Rules struct {
	Regexp   []string
	Protocol []string
	Relay    []RelayRule
}

// RelayRule 面板路由组 action=proxy：命中 Match 的连接改走 Outbound 描述的出站
type RelayRule struct {
	Id       int
	Match    []string
	Outbound string
}

// ResetNodeInfoCache 让下次 GetNodeInfo 必定返回完整配置
func (c *Client) ResetNodeInfoCache() {
	c.nodeEtag = ""
	c.responseBodyHash = ""
}

func (c *Client) GetNodeInfo(ctx context.Context) (node *NodeInfo, err error) {
	path := c.apiPath("/api/v1/server/UniProxy/config")
	r, err := c.client.
		R().
		SetContext(ctx).
		SetHeader("If-None-Match", c.nodeEtag).
		ForceContentType("application/json").
		Get(path)

	if r == nil {
		if err != nil {
			return nil, fmt.Errorf("get node info request error: %s", err)
		}
		return nil, fmt.Errorf("received nil response")
	}
	defer func() {
		if r.RawBody() != nil {
			r.RawBody().Close()
		}
	}()

	if r.StatusCode() == 304 {
		return nil, nil
	}
	if err = c.checkResponse(r, path, err); err != nil {
		return nil, err
	}

	hash := sha256.Sum256(r.Body())
	newBodyHash := hex.EncodeToString(hash[:])
	if c.responseBodyHash == newBodyHash {
		return nil, nil
	}
	c.responseBodyHash = newBodyHash
	c.nodeEtag = r.Header().Get("ETag")
	node = &NodeInfo{
		Id:   c.NodeId,
		Type: c.NodeType,
		RawDNS: RawDNS{
			DNSMap:  make(map[string]map[string]interface{}),
			DNSJson: []byte(""),
		},
	}
	// parse protocol params
	var cm *CommonNode
	switch c.NodeType {
	case "vmess", "vless":
		rsp := &VAllssNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode v2ray params error: %s", err)
		}
		if len(rsp.NetworkSettingsBack) > 0 {
			rsp.NetworkSettings = rsp.NetworkSettingsBack
			rsp.NetworkSettingsBack = nil
		}
		if rsp.TlsSettingsBack != nil {
			rsp.TlsSettings = *rsp.TlsSettingsBack
			rsp.TlsSettingsBack = nil
		}
		cm = &rsp.CommonNode
		node.VAllss = rsp
		node.Security = node.VAllss.Tls
	case "shadowsocks":
		rsp := &ShadowsocksNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode shadowsocks params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.Shadowsocks = rsp
		node.Security = None
	case "trojan":
		rsp := &TrojanNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode trojan params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.Trojan = rsp
		node.Security = rsp.Tls
		if node.Security == 0 {
			node.Security = Tls
		}
	case "tuic":
		rsp := &TuicNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode tuic params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.Tuic = rsp
		node.Security = Tls
	case "anytls":
		rsp := &AnyTlsNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode anytls params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.AnyTls = rsp
		node.Security = Tls
	case "hysteria":
		rsp := &HysteriaNode{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode hysteria params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.Hysteria = rsp
		node.Security = Tls
	case "hysteria2":
		rsp := &Hysteria2Node{}
		err = json.Unmarshal(r.Body(), rsp)
		if err != nil {
			return nil, fmt.Errorf("decode hysteria2 params error: %s", err)
		}
		cm = &rsp.CommonNode
		node.Hysteria2 = rsp
		node.Security = Tls
	}

	// parse rules and dns
	for i := range cm.Routes {
		var matchs []string
		if s, ok := cm.Routes[i].Match.(string); ok {
			matchs = strings.Split(s, ",")
		} else if sl, ok := cm.Routes[i].Match.([]string); ok {
			matchs = sl
		} else if temp, ok := cm.Routes[i].Match.([]interface{}); ok {
			matchs = make([]string, len(temp))
			for j := range temp {
				if s, ok := temp[j].(string); ok {
					matchs[j] = s
				}
			}
		} else {
			continue
		}
		switch cm.Routes[i].Action {
		case "block":
			for _, v := range matchs {
				if strings.HasPrefix(v, "protocol:") {
					// protocol
					node.Rules.Protocol = append(node.Rules.Protocol, strings.TrimPrefix(v, "protocol:"))
				} else {
					// domain
					node.Rules.Regexp = append(node.Rules.Regexp, strings.TrimPrefix(v, "regexp:"))
				}
			}
		case "dns":
			if len(matchs) == 0 {
				continue
			}
			var domains []string
			domains = append(domains, matchs...)
			if matchs[0] != "main" {
				node.RawDNS.DNSMap[strconv.Itoa(i)] = map[string]interface{}{
					"address": cm.Routes[i].ActionValue,
					"domains": domains,
				}
			} else {
				dns := []byte(strings.Join(matchs[1:], ""))
				node.RawDNS.DNSJson = dns
			}
		case "proxy":
			outbound := strings.TrimSpace(cm.Routes[i].ActionValue)
			if outbound == "" || len(matchs) == 0 {
				continue
			}
			node.Rules.Relay = append(node.Rules.Relay, RelayRule{
				Id:       cm.Routes[i].Id,
				Match:    matchs,
				Outbound: outbound,
			})
		}
	}

	// set interval
	node.PushInterval = intervalToTime(cm.BaseConfig.PushInterval)
	node.PullInterval = intervalToTime(cm.BaseConfig.PullInterval)

	if cm.CertConfig != nil && cm.CertConfig.CertMode != "" && cm.CertConfig.CertMode != "none" {
		node.CertConfig = cm.CertConfig
	}

	node.Common = cm
	// clear
	cm.Routes = nil
	cm.BaseConfig = nil

	return node, nil
}

func intervalToTime(i interface{}) time.Duration {
	if i == nil {
		return 0
	}
	switch v := i.(type) {
	case int:
		return time.Duration(v) * time.Second
	case float64:
		return time.Duration(v) * time.Second
	case string:
		n, _ := strconv.Atoi(v)
		return time.Duration(n) * time.Second
	default:
		rv := reflect.ValueOf(i)
		if rv.CanInt() {
			return time.Duration(rv.Int()) * time.Second
		}
		if rv.CanFloat() {
			return time.Duration(rv.Float()) * time.Second
		}
		return 0
	}
}
