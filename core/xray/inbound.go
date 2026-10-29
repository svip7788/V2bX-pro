package xray

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"encoding/json"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

type networkSettingsProxyProtocol struct {
	AcceptProxyProtocol bool `json:"acceptProxyProtocol"`
}

func detectProxyProtocolFromPanel(nodeInfo *panel.NodeInfo) bool {
	var raw json.RawMessage
	switch nodeInfo.Type {
	case "vmess", "vless":
		if nodeInfo.VAllss != nil {
			raw = nodeInfo.VAllss.NetworkSettings
		}
	case "trojan":
		if nodeInfo.Trojan != nil {
			raw = nodeInfo.Trojan.NetworkSettings
		}
	}
	if len(raw) == 0 {
		return false
	}
	n := &networkSettingsProxyProtocol{}
	if err := json.Unmarshal(raw, n); err != nil {
		return false
	}
	return n.AcceptProxyProtocol
}

// BuildInbound build Inbound config for different protocol
func buildInbound(option *conf.Options, nodeInfo *panel.NodeInfo, tag string) (*core.InboundHandlerConfig, error) {
	in := &coreConf.InboundDetourConfig{}
	var err error
	var network string
	switch nodeInfo.Type {
	case "vmess", "vless":
		err = buildV2ray(option, nodeInfo, in)
		network = nodeInfo.VAllss.Network
	case "trojan":
		err = buildTrojan(option, nodeInfo, in)
		if nodeInfo.Trojan.Network != "" {
			network = nodeInfo.Trojan.Network
		} else {
			network = "tcp"
		}
	case "shadowsocks":
		err = buildShadowsocks(option, nodeInfo, in)
		network = "tcp"
	case "hysteria":
		err = buildHysteria(nodeInfo, in)
		network = "hysteria"
	case "hysteria2":
		err = buildHysteria2(nodeInfo, in)
		network = "hysteria"
	case "tuic":
		err = buildTuic(nodeInfo, in)
		network = "tuic"
	case "anytls":
		err = buildAnyTLS(nodeInfo, in)
		network = nodeInfo.AnyTls.Network
		if network == "" {
			network = "tcp"
		}
	default:
		return nil, fmt.Errorf("unsupported node type: %s", nodeInfo.Type)
	}
	if err != nil {
		return nil, err
	}
	// Set network protocol
	// Set server port
	in.PortList = &coreConf.PortList{
		Range: []coreConf.PortRange{
			{
				From: uint32(nodeInfo.Common.ServerPort),
				To:   uint32(nodeInfo.Common.ServerPort),
			}},
	}
	// Set Listen IP address
	ipAddress := net.ParseAddress(option.ListenIP)
	in.ListenOn = &coreConf.Address{Address: ipAddress}
	// Set SniffingConfig
	sniffingConfig := &coreConf.SniffingConfig{
		Enabled:      true,
		// quic：HTTP/3 流量也按域名匹配路由组（如 Gemini 走转发）
		DestOverride: coreConf.StringList{"http", "tls", "quic"},
	}
	if option.XrayOptions.DisableSniffing {
		sniffingConfig.Enabled = false
	}
	in.SniffingConfig = sniffingConfig

	enableProxyProtocol := option.XrayOptions.EnableProxyProtocol
	if pp := detectProxyProtocolFromPanel(nodeInfo); pp {
		enableProxyProtocol = true
	}
	switch network {
	case "tcp":
		if in.StreamSetting != nil && in.StreamSetting.TCPSettings != nil {
			in.StreamSetting.TCPSettings.AcceptProxyProtocol = enableProxyProtocol || in.StreamSetting.TCPSettings.AcceptProxyProtocol
		} else {
			if in.StreamSetting == nil {
				t := coreConf.TransportProtocol("tcp")
				in.StreamSetting = &coreConf.StreamConfig{Network: &t}
			}
			in.StreamSetting.TCPSettings = &coreConf.TCPConfig{
				AcceptProxyProtocol: enableProxyProtocol,
			}
		}
	case "ws":
		if in.StreamSetting != nil && in.StreamSetting.WSSettings != nil {
			in.StreamSetting.WSSettings.AcceptProxyProtocol = enableProxyProtocol || in.StreamSetting.WSSettings.AcceptProxyProtocol
		} else {
			if in.StreamSetting == nil {
				t := coreConf.TransportProtocol("ws")
				in.StreamSetting = &coreConf.StreamConfig{Network: &t}
			}
			in.StreamSetting.WSSettings = &coreConf.WebSocketConfig{
				AcceptProxyProtocol: enableProxyProtocol,
			}
		}
	case "hysteria", "tuic":
		// QUIC-based protocols, no ProxyProtocol/TFO needed
	default:
		if in.StreamSetting == nil {
			t := coreConf.TransportProtocol(network)
			in.StreamSetting = &coreConf.StreamConfig{Network: &t}
		}
		if in.StreamSetting.SocketSettings == nil {
			in.StreamSetting.SocketSettings = &coreConf.SocketConfig{}
		}
		in.StreamSetting.SocketSettings.AcceptProxyProtocol = enableProxyProtocol
		in.StreamSetting.SocketSettings.TFO = option.XrayOptions.EnableTFO
	}
	// Set TLS or Reality settings
	switch nodeInfo.Security {
	case panel.Tls:
		// Normal tls
		if option.CertConfig == nil {
			return nil, errors.New("the CertConfig is not vail")
		}
		switch option.CertConfig.CertMode {
		case "none", "":
			break // disable
		default:
			in.StreamSetting.Security = "tls"
			tlsCfg := &coreConf.TLSConfig{
				Certs: []*coreConf.TLSCertConfig{
					{
						CertFile:     option.CertConfig.CertFile,
						KeyFile:      option.CertConfig.KeyFile,
						OcspStapling: 3600,
					},
				},
				RejectUnknownSNI: option.CertConfig.RejectUnknownSni,
			}
			if nodeInfo.Type == "hysteria" || nodeInfo.Type == "hysteria2" || nodeInfo.Type == "tuic" {
				alpnList := &coreConf.StringList{"h3"}
				tlsCfg.ALPN = alpnList
			}
			in.StreamSetting.TLSSettings = tlsCfg
		}
	case panel.Reality:
		in.StreamSetting.Security = "reality"
		var tlsSettings panel.TlsSettings
		var realityConfig panel.RealityConfig
		switch nodeInfo.Type {
		case "vmess", "vless":
			tlsSettings = nodeInfo.VAllss.TlsSettings
			realityConfig = nodeInfo.VAllss.RealityConfig
		case "trojan":
			tlsSettings = nodeInfo.Trojan.TlsSettings
		}
		dest := tlsSettings.Dest
		if dest == "" {
			dest = tlsSettings.ServerName
		}
		xver := tlsSettings.Xver
		if xver == 0 {
			xver = realityConfig.Xver
		}
		d, err := json.Marshal(fmt.Sprintf(
			"%s:%s",
			dest,
			tlsSettings.ServerPort))
		if err != nil {
			return nil, fmt.Errorf("marshal reality dest error: %s", err)
		}
		mtd, _ := time.ParseDuration(realityConfig.MaxTimeDiff)
		in.StreamSetting.REALITYSettings = &coreConf.REALITYConfig{
			Dest:         d,
			Xver:         xver,
			Show:         false,
			ServerNames:  []string{tlsSettings.ServerName},
			PrivateKey:   tlsSettings.PrivateKey,
			MinClientVer: realityConfig.MinClientVer,
			MaxClientVer: realityConfig.MaxClientVer,
			MaxTimeDiff:  uint64(mtd.Microseconds()),
			ShortIds:     []string{tlsSettings.ShortId},
			Mldsa65Seed:  tlsSettings.Mldsa65Seed,
		}
	default:
		break
	}
	in.Tag = tag
	return in.Build()
}

func buildV2ray(config *conf.Options, nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	v := nodeInfo.VAllss
	if nodeInfo.Type == "vless" {
		//Set vless
		inbound.Protocol = "vless"
		if config.XrayOptions.EnableFallback {
			// Set fallback
			fallbackConfigs, err := buildVlessFallbacks(config.XrayOptions.FallBackConfigs)
			if err != nil {
				return err
			}
			s, err := json.Marshal(&coreConf.VLessInboundConfig{
				Decryption: "none",
				Fallbacks:  fallbackConfigs,
			})
			if err != nil {
				return fmt.Errorf("marshal vless fallback config error: %s", err)
			}
			inbound.Settings = (*json.RawMessage)(&s)
		} else {
			var err error
			decryption, err := resolveVLESSDecryption(nodeInfo.VAllss)
			if err != nil {
				return err
			}
			s, err := json.Marshal(&coreConf.VLessInboundConfig{
				Decryption: decryption,
			})
			if err != nil {
				return fmt.Errorf("marshal vless config error: %s", err)
			}
			inbound.Settings = (*json.RawMessage)(&s)
		}
	} else {
		// Set vmess
		inbound.Protocol = "vmess"
		var err error
		s, err := json.Marshal(&coreConf.VMessInboundConfig{})
		if err != nil {
			return fmt.Errorf("marshal vmess settings error: %s", err)
		}
		inbound.Settings = (*json.RawMessage)(&s)
	}
	if len(v.NetworkSettings) == 0 {
		return nil
	}

	t := coreConf.TransportProtocol(v.Network)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	switch v.Network {
	case "tcp":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.TCPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal tcp settings error: %s", err)
		}
	case "ws":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.WSSettings)
		if err != nil {
			return fmt.Errorf("unmarshal ws settings error: %s", err)
		}
	case "grpc":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.GRPCSettings)
		if err != nil {
			return fmt.Errorf("unmarshal grpc settings error: %s", err)
		}
	case "httpupgrade":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.HTTPUPGRADESettings)
		if err != nil {
			return fmt.Errorf("unmarshal httpupgrade settings error: %s", err)
		}
	case "splithttp", "xhttp":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.SplitHTTPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal xhttp settings error: %s", err)
		}
	default:
		return errors.New("the network type is not vail")
	}
	return nil
}

func resolveVLESSDecryption(v *panel.VAllssNode) (string, error) {
	if v == nil {
		return "none", nil
	}
	// Prefer the final decryption string provided by the panel.
	if decryption := strings.TrimSpace(v.Decryption); decryption != "" {
		return decryption, nil
	}
	if v.Encryption == "" {
		return "none", nil
	}
	switch v.Encryption {
	case "mlkem768x25519plus":
		encSettings := v.EncryptionSettings
		parts := []string{
			"mlkem768x25519plus",
			encSettings.Mode,
			encSettings.Ticket,
		}
		if encSettings.ServerPadding != "" {
			parts = append(parts, encSettings.ServerPadding)
		}
		parts = append(parts, encSettings.PrivateKey)
		return strings.Join(parts, "."), nil
	default:
		return "", fmt.Errorf("vless decryption method %s is not support", v.Encryption)
	}
}

func buildTrojan(config *conf.Options, nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "trojan"
	v := nodeInfo.Trojan
	if config.XrayOptions.EnableFallback {
		// Set fallback
		fallbackConfigs, err := buildTrojanFallbacks(config.XrayOptions.FallBackConfigs)
		if err != nil {
			return err
		}
		s, err := json.Marshal(&coreConf.TrojanServerConfig{
			Fallbacks: fallbackConfigs,
		})
		if err != nil {
			return fmt.Errorf("marshal trojan fallback config error: %s", err)
		}
		inbound.Settings = (*json.RawMessage)(&s)
	} else {
		s := []byte("{}")
		inbound.Settings = (*json.RawMessage)(&s)
	}
	network := v.Network
	if network == "" {
		network = "tcp"
	}
	t := coreConf.TransportProtocol(network)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	if len(v.NetworkSettings) == 0 {
		return nil
	}
	switch network {
	case "tcp":
		if err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.TCPSettings); err != nil {
			return fmt.Errorf("unmarshal tcp settings error: %s", err)
		}
	case "ws":
		if err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.WSSettings); err != nil {
			return fmt.Errorf("unmarshal ws settings error: %s", err)
		}
	case "grpc":
		if err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.GRPCSettings); err != nil {
			return fmt.Errorf("unmarshal grpc settings error: %s", err)
		}
	case "httpupgrade":
		if err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.HTTPUPGRADESettings); err != nil {
			return fmt.Errorf("unmarshal httpupgrade settings error: %s", err)
		}
	case "splithttp", "xhttp":
		if err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.SplitHTTPSettings); err != nil {
			return fmt.Errorf("unmarshal xhttp settings error: %s", err)
		}
	default:
		return errors.New("the network type is not vail")
	}
	return nil
}

type shadowsocksHTTPNetworkSettings struct {
	AcceptProxyProtocol bool   `json:"acceptProxyProtocol"`
	Path                string `json:"path"`
	Host                string `json:"Host"`
}

func buildShadowsocks(config *conf.Options, nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "shadowsocks"
	s := nodeInfo.Shadowsocks
	settings := &coreConf.ShadowsocksServerConfig{
		Cipher: s.Cipher,
	}
	p := make([]byte, 32)
	_, err := rand.Read(p)
	if err != nil {
		return fmt.Errorf("generate random password error: %s", err)
	}
	randomPasswd := hex.EncodeToString(p)
	cipher := s.Cipher
	if s.ServerKey != "" {
		settings.Password = s.ServerKey
		randomPasswd = base64.StdEncoding.EncodeToString([]byte(randomPasswd))
		cipher = ""
	}
	defaultSSuser := &coreConf.ShadowsocksUserConfig{
		Cipher:   cipher,
		Password: randomPasswd,
	}
	settings.Users = append(settings.Users, defaultSSuser)
	settings.NetworkList = &coreConf.NetworkList{"tcp", "udp"}

	if len(s.NetworkSettings) != 0 {
		shttp := &shadowsocksHTTPNetworkSettings{}
		if err := json.Unmarshal(s.NetworkSettings, shttp); err != nil {
			return fmt.Errorf("unmarshal shadowsocks network settings error: %s", err)
		}
		if shttp.Path != "" || shttp.Host != "" {
			settings.NetworkList = &coreConf.NetworkList{"tcp"}
		}
		if shttp.AcceptProxyProtocol || shttp.Path != "" || shttp.Host != "" {
			t := coreConf.TransportProtocol("tcp")
			inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
			inbound.StreamSetting.TCPSettings = &coreConf.TCPConfig{
				AcceptProxyProtocol: shttp.AcceptProxyProtocol,
			}
			if shttp.Path != "" || shttp.Host != "" {
				httpHeader := map[string]interface{}{
					"type":    "http",
					"request": map[string]interface{}{},
				}
				request := httpHeader["request"].(map[string]interface{})
				path := shttp.Path
				if path == "" {
					path = "/"
				}
				request["path"] = []string{path}
				if shttp.Host != "" {
					request["headers"] = map[string]interface{}{
						"Host": []string{shttp.Host},
					}
				}
				headerJSON, err := json.Marshal(httpHeader)
				if err == nil {
					inbound.StreamSetting.TCPSettings.HeaderConfig = json.RawMessage(headerJSON)
				}
			}
		}
	}
	if inbound.StreamSetting == nil {
		t := coreConf.TransportProtocol("tcp")
		inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	}

	sets, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("marshal shadowsocks settings error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&sets)
	return nil
}

func buildHysteria(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "hysteria"
	s := nodeInfo.Hysteria
	settings := &coreConf.HysteriaServerConfig{
		Version: 1,
	}
	t := coreConf.TransportProtocol("hysteria")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	hysteriaSetting := &coreConf.HysteriaConfig{
		Version: 1,
	}
	var finalMask *coreConf.FinalMask
	if s.UpMbps > 0 || s.DownMbps > 0 {
		up := coreConf.Bandwidth(strconv.Itoa(s.UpMbps) + "mbps")
		down := coreConf.Bandwidth(strconv.Itoa(s.DownMbps) + "mbps")
		finalMask = &coreConf.FinalMask{
			QuicParams: &coreConf.QuicParamsConfig{
				Congestion: "force-brutal",
				BrutalUp:   up,
				BrutalDown: down,
			},
		}
	}
	if s.Obfs != "" {
		rawObfsJSON := json.RawMessage(fmt.Sprintf(`{"password":"%s"}`, s.Obfs))
		udp := []coreConf.Mask{
			{
				Type:     "salamander",
				Settings: &rawObfsJSON,
			},
		}
		if finalMask == nil {
			finalMask = &coreConf.FinalMask{}
		}
		finalMask.Udp = udp
	}
	inbound.StreamSetting.FinalMask = finalMask
	inbound.StreamSetting.HysteriaSettings = hysteriaSetting
	sets, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("marshal hysteria settings error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&sets)
	return nil
}

func buildHysteria2(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "hysteria"
	s := nodeInfo.Hysteria2
	settings := &coreConf.HysteriaServerConfig{
		Version: 2,
	}

	t := coreConf.TransportProtocol("hysteria")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	hysteriaSetting := &coreConf.HysteriaConfig{
		Version: 2,
	}
	var finalMask *coreConf.FinalMask
	if !s.Ignore_Client_Bandwidth && (s.UpMbps > 0 || s.DownMbps > 0) {
		up := coreConf.Bandwidth(strconv.Itoa(s.UpMbps) + "mbps")
		down := coreConf.Bandwidth(strconv.Itoa(s.DownMbps) + "mbps")
		finalMask = &coreConf.FinalMask{
			QuicParams: &coreConf.QuicParamsConfig{
				Congestion: "force-brutal",
				BrutalUp:   up,
				BrutalDown: down,
			},
		}
	}
	if s.ObfsType != "" && s.ObfsPassword != "" {
		rawObfsJSON := json.RawMessage(fmt.Sprintf(`{"password":"%s"}`, s.ObfsPassword))
		udp := []coreConf.Mask{
			{
				Type:     s.ObfsType,
				Settings: &rawObfsJSON,
			},
		}
		if finalMask == nil {
			finalMask = &coreConf.FinalMask{}
		}
		finalMask.Udp = udp
	}
	inbound.StreamSetting.FinalMask = finalMask
	inbound.StreamSetting.HysteriaSettings = hysteriaSetting
	sets, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("marshal hysteria2 settings error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&sets)
	return nil
}

func buildTuic(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "tuic"
	s := nodeInfo.Tuic
	settings := &coreConf.TuicServerConfig{
		CongestionControl: s.CongestionControl,
		ZeroRttHandshake:  s.ZeroRTTHandshake,
	}
	t := coreConf.TransportProtocol("tuic")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	sets, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("marshal tuic settings error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&sets)
	return nil
}

func buildAnyTLS(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "anytls"
	v := nodeInfo.AnyTls
	settings := &coreConf.AnyTLSServerConfig{
		PaddingScheme: v.PaddingScheme,
	}
	network := v.Network
	if network == "" {
		network = "tcp"
	}
	t := coreConf.TransportProtocol(network)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	if len(v.NetworkSettings) != 0 {
		switch network {
		case "tcp":
			if err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.TCPSettings); err != nil {
				return fmt.Errorf("unmarshal tcp settings error: %s", err)
			}
		case "ws":
			if err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.WSSettings); err != nil {
				return fmt.Errorf("unmarshal ws settings error: %s", err)
			}
		case "grpc":
			if err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.GRPCSettings); err != nil {
				return fmt.Errorf("unmarshal grpc settings error: %s", err)
			}
		case "httpupgrade":
			if err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.HTTPUPGRADESettings); err != nil {
				return fmt.Errorf("unmarshal httpupgrade settings error: %s", err)
			}
		case "splithttp", "xhttp":
			if err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.SplitHTTPSettings); err != nil {
				return fmt.Errorf("unmarshal xhttp settings error: %s", err)
			}
		}
	}
	sets, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("marshal anytls settings error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&sets)
	return nil
}

func buildVlessFallbacks(fallbackConfigs []conf.FallBackConfigForXray) ([]*coreConf.VLessInboundFallback, error) {
	if fallbackConfigs == nil {
		return nil, fmt.Errorf("you must provide FallBackConfigs")
	}
	vlessFallBacks := make([]*coreConf.VLessInboundFallback, len(fallbackConfigs))
	for i, c := range fallbackConfigs {
		if c.Dest == "" {
			return nil, fmt.Errorf("dest is required for fallback fialed")
		}
		var dest json.RawMessage
		dest, err := json.Marshal(c.Dest)
		if err != nil {
			return nil, fmt.Errorf("marshal dest %s config fialed: %s", dest, err)
		}
		vlessFallBacks[i] = &coreConf.VLessInboundFallback{
			Name: c.SNI,
			Alpn: c.Alpn,
			Path: c.Path,
			Dest: dest,
			Xver: c.ProxyProtocolVer,
		}
	}
	return vlessFallBacks, nil
}

func buildTrojanFallbacks(fallbackConfigs []conf.FallBackConfigForXray) ([]*coreConf.TrojanInboundFallback, error) {
	if fallbackConfigs == nil {
		return nil, fmt.Errorf("you must provide FallBackConfigs")
	}

	trojanFallBacks := make([]*coreConf.TrojanInboundFallback, len(fallbackConfigs))
	for i, c := range fallbackConfigs {

		if c.Dest == "" {
			return nil, fmt.Errorf("dest is required for fallback fialed")
		}

		var dest json.RawMessage
		dest, err := json.Marshal(c.Dest)
		if err != nil {
			return nil, fmt.Errorf("marshal dest %s config fialed: %s", dest, err)
		}
		trojanFallBacks[i] = &coreConf.TrojanInboundFallback{
			Name: c.SNI,
			Alpn: c.Alpn,
			Path: c.Path,
			Dest: dest,
			Xver: c.ProxyProtocolVer,
		}
	}
	return trojanFallBacks, nil
}
