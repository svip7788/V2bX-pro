package xray

import (
	"encoding/json"
	"testing"

	"github.com/InazumaV/V2bX/api/panel"
	coreConf "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/anytls"
)

func TestResolveVLESSDecryptionPrefersPanelDecryption(t *testing.T) {
	v := &panel.VAllssNode{
		Decryption: "mlkem768x25519plus.native.600s.100-111-1111.test-private-key",
		Encryption: "mlkem768x25519plus",
		EncryptionSettings: panel.EncSettings{
			Mode:          "random",
			Ticket:        "0rtt",
			ServerPadding: "100-111-1111",
			PrivateKey:    "legacy-private-key",
		},
	}

	got, err := resolveVLESSDecryption(v)
	if err != nil {
		t.Fatalf("resolveVLESSDecryption returned error: %v", err)
	}
	if got != v.Decryption {
		t.Fatalf("expected panel decryption %q, got %q", v.Decryption, got)
	}
}

func TestResolveVLESSDecryptionBuildsLegacyFormat(t *testing.T) {
	v := &panel.VAllssNode{
		Encryption: "mlkem768x25519plus",
		EncryptionSettings: panel.EncSettings{
			Mode:          "native",
			Ticket:        "600s",
			ServerPadding: "100-111-1111",
			PrivateKey:    "test-private-key",
		},
	}

	got, err := resolveVLESSDecryption(v)
	if err != nil {
		t.Fatalf("resolveVLESSDecryption returned error: %v", err)
	}

	want := "mlkem768x25519plus.native.600s.100-111-1111.test-private-key"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestResolveVLESSDecryptionDefaultsToNone(t *testing.T) {
	got, err := resolveVLESSDecryption(&panel.VAllssNode{})
	if err != nil {
		t.Fatalf("resolveVLESSDecryption returned error: %v", err)
	}
	if got != "none" {
		t.Fatalf("expected %q, got %q", "none", got)
	}
}

func TestResolveVLESSDecryptionRejectsUnsupportedMethod(t *testing.T) {
	_, err := resolveVLESSDecryption(&panel.VAllssNode{
		Encryption: "unsupported",
	})
	if err == nil {
		t.Fatal("expected error for unsupported decryption method")
	}
}

func TestBuildAnyTLSFallback(t *testing.T) {
	info := &panel.NodeInfo{AnyTls: &panel.AnyTlsNode{FallbackAddr: "127.0.0.1", FallbackPort: 80}}
	in := &coreConf.InboundDetourConfig{}
	if err := buildAnyTLS(info, in); err != nil {
		t.Fatal(err)
	}
	var s coreConf.AnyTLSServerConfig
	if err := json.Unmarshal(*in.Settings, &s); err != nil {
		t.Fatal(err)
	}
	msg, err := s.Build()
	if err != nil {
		t.Fatal(err)
	}
	if c := msg.(*anytls.ServerConfig); c.FallbackAddr != "127.0.0.1" || c.FallbackPort != 80 {
		t.Fatalf("fallback not applied: %+v", c)
	}

	info.AnyTls.FallbackPort = 0
	in = &coreConf.InboundDetourConfig{}
	if err := buildAnyTLS(info, in); err != nil {
		t.Fatal(err)
	}
	s = coreConf.AnyTLSServerConfig{}
	if err := json.Unmarshal(*in.Settings, &s); err != nil {
		t.Fatal(err)
	}
	if s.FallbackAddr != "" || s.FallbackPort != 0 {
		t.Fatalf("incomplete fallback should be ignored: %+v", s)
	}
}
