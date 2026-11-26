package xray

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/InazumaV/V2bX/conf"
	"github.com/xtls/xray-core/app/proxyman"
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

func TestBuildOutboundDefaultsToUseIPv4(t *testing.T) {
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
		t.Fatalf("expected SocketSettings for default UseIPv4 strategy, got %+v", sc.StreamSettings)
	}
	if got := sc.StreamSettings.SocketSettings.DomainStrategy; got != internet.DomainStrategy_USE_IP4 {
		t.Fatalf("expected DomainStrategy_USE_IP4, got %v", got)
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
