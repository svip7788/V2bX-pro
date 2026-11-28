package xray

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/InazumaV/V2bX/conf"
	"github.com/xtls/xray-core/app/proxyman"
	coreConf "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
)

func TestResolveOptionalConfigPathPrefersExplicitPath(t *testing.T) {
	cfg := &conf.XrayConfig{
		AssetPath: "/tmp/assets",
	}
	cfg.DnsConfigPath = "/tmp/custom.json"

	got, auto := cfg.ResolveDNSConfigPath()
	if got != "/tmp/custom.json" {
		t.Fatalf("expected explicit path to win, got %q", got)
	}
	if auto {
		t.Fatal("explicit path should not be marked as auto discovered")
	}
}

func TestResolveOptionalConfigPathAutoDiscoversBundledFile(t *testing.T) {
	dir := t.TempDir()
	candidate := filepath.Join(dir, "dns.json")
	if err := os.WriteFile(candidate, []byte(`{}`), 0644); err != nil {
		t.Fatalf("write dns config failed: %v", err)
	}

	cfg := &conf.XrayConfig{
		AssetPath: dir,
	}
	got, auto := cfg.ResolveDNSConfigPath()
	if got != candidate {
		t.Fatalf("expected %q, got %q", candidate, got)
	}
	if !auto {
		t.Fatal("expected auto discovered path")
	}
}

func TestResolveOptionalConfigPathReturnsEmptyWhenMissing(t *testing.T) {
	cfg := &conf.XrayConfig{
		AssetPath: t.TempDir(),
	}
	got, auto := cfg.ResolveDNSConfigPath()
	if got != "" {
		t.Fatalf("expected empty path, got %q", got)
	}
	if auto {
		t.Fatal("missing file should not be marked as auto discovered")
	}
}

func TestDefaultDNSServersPreferLocalResolver(t *testing.T) {
	servers := defaultDNSServers()
	if len(servers) == 0 {
		t.Fatal("expected built-in dns servers")
	}
	if servers[0] == nil {
		t.Fatal("first dns server should not be nil")
	}
}

func TestBuildOutboundDefaultsToForceIPv4(t *testing.T) {
	opts := &conf.Options{
		SendIP:      "0.0.0.0",
		XrayOptions: conf.NewXrayOptions(),
	}
	ob, err := buildOutbound(opts, "node1")
	if err != nil {
		t.Fatalf("buildOutbound failed: %v", err)
	}
	raw, err := ob.SenderSettings.GetInstance()
	if err != nil {
		t.Fatalf("get SenderSettings failed: %v", err)
	}
	sc := raw.(*proxyman.SenderConfig)
	if sc.StreamSettings == nil || sc.StreamSettings.SocketSettings == nil {
		t.Fatalf("expected SocketSettings for default ForceIPv4 strategy, got %+v", sc.StreamSettings)
	}
	if got := sc.StreamSettings.SocketSettings.DomainStrategy; got != internet.DomainStrategy_FORCE_IP4 {
		t.Fatalf("expected DomainStrategy_FORCE_IP4, got %v", got)
	}

	opts.XrayOptions.EnableDNS = false
	obNoDNS, err := buildOutbound(opts, "node2")
	if err != nil {
		t.Fatalf("buildOutbound (no dns) failed: %v", err)
	}
	rawNoDNS, err := obNoDNS.SenderSettings.GetInstance()
	if err != nil {
		t.Fatalf("get SenderSettings failed: %v", err)
	}
	scNoDNS := rawNoDNS.(*proxyman.SenderConfig)
	if scNoDNS.StreamSettings != nil && scNoDNS.StreamSettings.SocketSettings != nil &&
		scNoDNS.StreamSettings.SocketSettings.DomainStrategy != internet.DomainStrategy_AS_IS {
		t.Fatalf("expected AS_IS when EnableDNS=false, got %v", scNoDNS.StreamSettings.SocketSettings.DomainStrategy)
	}
}

func TestBuildCustomOutboundsDefaultsIPv4OutToForceIPv4(t *testing.T) {
	raw := `[
		{"tag":"IPv4_out","protocol":"freedom","settings":{}},
		{"tag":"IPv6_out","protocol":"freedom","settings":{"domainStrategy":"UseIPv6"}},
		{"tag":"block","protocol":"blackhole","settings":{}}
	]`
	var cfgs []coreConf.OutboundDetourConfig
	if err := json.Unmarshal([]byte(raw), &cfgs); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	obs, err := buildCustomOutbounds(cfgs)
	if err != nil {
		t.Fatalf("buildCustomOutbounds failed: %v", err)
	}
	rawSC, err := obs[0].SenderSettings.GetInstance()
	if err != nil {
		t.Fatalf("get SenderSettings failed: %v", err)
	}
	sc := rawSC.(*proxyman.SenderConfig)
	if sc.StreamSettings == nil || sc.StreamSettings.SocketSettings == nil ||
		sc.StreamSettings.SocketSettings.DomainStrategy != internet.DomainStrategy_FORCE_IP4 {
		t.Fatalf("expected IPv4_out to default to FORCE_IP4, got %+v", sc.StreamSettings)
	}

	rawV6, err := obs[1].SenderSettings.GetInstance()
	if err != nil {
		t.Fatalf("get v6 SenderSettings failed: %v", err)
	}
	scV6 := rawV6.(*proxyman.SenderConfig)
	if scV6.StreamSettings == nil || scV6.StreamSettings.SocketSettings == nil ||
		scV6.StreamSettings.SocketSettings.DomainStrategy != internet.DomainStrategy_USE_IP6 {
		t.Fatalf("expected IPv6_out to stay USE_IP6, got %+v", scV6.StreamSettings)
	}
}

func TestBuildCustomOutboundsRespectsExplicitIPv4OutStrategy(t *testing.T) {
	raw := `[{"tag":"IPv4_out","protocol":"freedom","settings":{"domainStrategy":"AsIs"}}]`
	var cfgs []coreConf.OutboundDetourConfig
	if err := json.Unmarshal([]byte(raw), &cfgs); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	obs, err := buildCustomOutbounds(cfgs)
	if err != nil {
		t.Fatalf("buildCustomOutbounds failed: %v", err)
	}
	rawSC, err := obs[0].SenderSettings.GetInstance()
	if err != nil {
		t.Fatalf("get SenderSettings failed: %v", err)
	}
	sc := rawSC.(*proxyman.SenderConfig)
	if sc.StreamSettings != nil && sc.StreamSettings.SocketSettings != nil &&
		sc.StreamSettings.SocketSettings.DomainStrategy != internet.DomainStrategy_AS_IS {
		t.Fatalf("expected explicit AsIs to be preserved, got %v", sc.StreamSettings.SocketSettings.DomainStrategy)
	}
}

func TestIsLegacyDefaultDNS(t *testing.T) {
	cases := []struct {
		name string
		json string
		want bool
	}{
		{"old installer", `{"servers":["1.1.1.1","8.8.8.8","localhost"],"tag":"dns_inbound"}`, true},
		{"built-in doh list", `{"servers":["localhost","https://1.1.1.1/dns-query","tcp-tls://1.1.1.1","tcp://1.1.1.1","1.1.1.1","https://8.8.8.8/dns-query","tcp://8.8.8.8","8.8.8.8"],"queryStrategy":"UseIPv4","tag":"dns_inbound"}`, true},
		{"system only", `{"servers":["localhost"],"tag":"dns_inbound"}`, false},
		{"empty", `{}`, false},
		{"other resolver", `{"servers":["9.9.9.9","localhost"]}`, false},
		{"object server", `{"servers":[{"address":"1.1.1.1"},"localhost"]}`, false},
		{"scoped server", `{"servers":[{"address":"1.1.1.1","domains":["geosite:netflix"]},"localhost"]}`, false},
		{"has hosts", `{"servers":["1.1.1.1"],"hosts":{"a.com":"1.2.3.4"}}`, false},
		{"invalid", `{bad`, false},
	}
	for _, c := range cases {
		if got := isLegacyDefaultDNS([]byte(c.json)); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestMigrateLegacyDNSFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.json")
	old := []byte(`{"servers":["1.1.1.1","8.8.8.8","localhost"],"queryStrategy":"UseIPv4","tag":"dns_inbound"}`)
	if err := os.WriteFile(path, old, 0644); err != nil {
		t.Fatal(err)
	}
	migrateLegacyDNSFile(path, old)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if isLegacyDefaultDNS(data) {
		t.Fatalf("still legacy: %s", data)
	}
	cfg := &coreConf.DNSConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Servers) != 1 || cfg.Servers[0].Address.String() != "localhost" || cfg.QueryStrategy != "UseIPv4" || cfg.Tag != "dns_inbound" {
		t.Fatalf("cfg=%s", data)
	}
	if _, err := cfg.Build(); err != nil {
		t.Fatal(err)
	}
	if backup, _ := os.ReadFile(path + ".legacy"); string(backup) != string(old) {
		t.Fatalf("backup=%s", backup)
	}
}
