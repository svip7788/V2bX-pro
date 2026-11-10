package conf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMachineConfigLoad(t *testing.T) {
	c := New()
	data := `{"Log":{"Level":"error"},"Machine":{"ApiHost":"https://p.example","MachineID":3,"Token":"tk","Core":"auto","NodeDefaults":{"ListenIP":"1.2.3.4","CertConfig":{"CertMode":"file"}}}}`
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	if err := c.LoadFromPath(p); err != nil {
		t.Fatal(err)
	}
	if !c.MachineConfig.Enabled() || c.MachineConfig.MachineID != 3 {
		t.Fatalf("machine config not loaded: %+v", c.MachineConfig)
	}

	nc, err := c.MachineConfig.NodeConfig(7, "vless")
	if err != nil {
		t.Fatal(err)
	}
	if nc.ApiConfig.NodeID != 7 || nc.ApiConfig.Key != "tk" || nc.ApiConfig.APIHost != "https://p.example" {
		t.Fatalf("bad api config: %+v", nc.ApiConfig)
	}
	if nc.Options.Core != "xray" || nc.Options.XrayOptions == nil {
		t.Fatalf("xray options missing: %+v", nc.Options)
	}
	if nc.Options.ListenIP != "1.2.3.4" {
		t.Fatalf("NodeDefaults not applied: %s", nc.Options.ListenIP)
	}
	if nc.Options.CertConfig.CertMode != "file" || nc.Options.CertConfig.CertFile != "/etc/V2bX/cert/node7.crt" {
		t.Fatalf("CertConfig not merged: %+v", nc.Options.CertConfig)
	}
}

func TestMachineQUICNodeUsesXray(t *testing.T) {
	m := &MachineConfig{APIHost: "http://p/", MachineID: 1, Token: "t", Core: "sing"}
	if NormalizeMachineNodeType("hysteria") != "" {
		t.Fatal("hysteria v1 should be unsupported")
	}
	for _, typ := range []string{"hysteria2", "tuic"} {
		nc, err := m.NodeConfig(5, typ)
		if err != nil {
			t.Fatal(err)
		}
		if nc.ApiConfig.APIHost != "http://p" {
			t.Fatalf("trailing slash not trimmed: %s", nc.ApiConfig.APIHost)
		}
		if nc.Options.Core != "xray" || nc.Options.XrayOptions == nil || nc.Options.CertConfig.CertMode != "self" {
			t.Fatalf("%s: bad options: %+v %+v", typ, nc.Options, nc.Options.CertConfig)
		}
	}
}

func TestLegacySingConfigFallsBackToXray(t *testing.T) {
	data := `{"Cores":[{"Type":"sing","Name":"s1","Log":{"Level":"error"}}],
"Nodes":[{"ApiHost":"http://p","ApiKey":"k","NodeID":1,"NodeType":"hysteria2","Core":"sing","CoreName":"s1","EnableSniff":true}]}`
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	c := New()
	if err := c.LoadFromPath(p); err != nil {
		t.Fatal(err)
	}
	if len(c.CoresConfig) != 1 || c.CoresConfig[0].Type != "xray" || c.CoresConfig[0].XrayConfig == nil {
		t.Fatalf("sing-only Cores should become default xray, got %+v", c.CoresConfig)
	}
	o := c.NodeConfig[0].Options
	if o.Core != "xray" || o.XrayOptions == nil || o.CoreName != "" {
		t.Fatalf("sing node should switch to xray: %+v", o)
	}
}

func TestMachineXrayAnyTLSNodeOptions(t *testing.T) {
	m := &MachineConfig{APIHost: "http://p", MachineID: 1, Token: "t"}
	nc, err := m.NodeConfig(6, "anytls")
	if err != nil {
		t.Fatal(err)
	}
	if nc.Options.XrayOptions == nil || nc.Options.ListenIP != "0.0.0.0" || nc.Options.CertConfig.CertMode != "self" {
		t.Fatalf("bad xray anytls options: %+v %+v", nc.Options, nc.Options.CertConfig)
	}
}

func TestNormalizeMachineNodeType(t *testing.T) {
	if NormalizeMachineNodeType("V2ray") != "vmess" || NormalizeMachineNodeType("socks") != "" {
		t.Fatal("normalize failed")
	}
}
