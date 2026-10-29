package relay

import (
	"net/netip"
	"testing"
)

func TestMatcher(t *testing.T) {
	m, err := NewMatcher([]string{"port:22", "port:8000-8100", "openai.com", "*.claude.ai", "full:gemini.google.com", "keyword:anthropic", "ip:1.2.3.0/24", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host string
		ip   string
		port uint16
		want bool
	}{
		{"", "8.8.8.8", 22, true},
		{"", "8.8.8.8", 8050, true},
		{"", "8.8.8.8", 443, false},
		{"api.openai.com", "", 443, true},
		{"openai.com", "", 443, true},
		{"notopenai.com", "", 443, false},
		{"claude.ai", "", 443, true},
		{"gemini.google.com", "", 443, true},
		{"www.google.com", "", 443, false},
		{"cdn.anthropic.com", "", 443, true},
		{"", "1.2.3.99", 443, true},
		{"", "2001:db8::1", 443, true},
	}
	for _, c := range cases {
		var ip netip.Addr
		if c.ip != "" {
			ip = netip.MustParseAddr(c.ip)
		}
		if got := m.Match(c.host, ip, c.port); got != c.want {
			t.Errorf("Match(%q,%q,%d)=%v want %v", c.host, c.ip, c.port, got, c.want)
		}
	}
	if _, err := NewMatcher([]string{"port:abc"}); err == nil {
		t.Error("expected invalid port error")
	}
}

func TestBypass(t *testing.T) {
	for _, s := range []string{"10.0.0.1", "127.0.0.1", "192.168.1.1", "::1", "fe80::1"} {
		if !Bypass(netip.MustParseAddr(s)) {
			t.Errorf("%s should bypass", s)
		}
	}
	if Bypass(netip.MustParseAddr("8.8.8.8")) || Bypass(netip.Addr{}) {
		t.Error("public/invalid ip should not bypass")
	}
	if !BypassHost("localhost") || !BypassHost("a.localhost.") || BypassHost("openai.com") {
		t.Error("BypassHost mismatch")
	}
}

func TestParseOutbound(t *testing.T) {
	o, err := ParseOutbound("ss://2022-blake3-aes-128-gcm:abc+/123==@1.2.3.4:8388#hk")
	if err != nil || o.Type != TypeShadowsocks || o.Method != "2022-blake3-aes-128-gcm" || o.Password != "abc+/123==" || o.Port != 8388 {
		t.Fatalf("plain ss: %+v %v", o, err)
	}
	// base64("aes-128-gcm:pass")
	o, err = ParseOutbound("ss://YWVzLTEyOC1nY206cGFzcw@relay.example.com:443")
	if err != nil || o.Method != "aes-128-gcm" || o.Password != "pass" || o.Server != "relay.example.com" {
		t.Fatalf("base64 ss: %+v %v", o, err)
	}
	o, err = ParseOutbound("socks5://u:p%40w@[2001:db8::1]:1080")
	if err != nil || o.Type != TypeSocks || o.Username != "u" || o.Password != "p@w" || o.Server != "2001:db8::1" {
		t.Fatalf("socks: %+v %v", o, err)
	}
	o, err = ParseOutbound("http://1.1.1.1:3128")
	if err != nil || o.Type != TypeHTTP || o.Username != "" {
		t.Fatalf("http: %+v %v", o, err)
	}
	o, err = ParseOutbound(`{"protocol":"freedom"}`)
	if err != nil || o.Raw == nil {
		t.Fatalf("json: %+v %v", o, err)
	}
	o, err = ParseOutbound("IPv6_out")
	if err != nil || o.Ref != "IPv6_out" {
		t.Fatalf("ref: %+v %v", o, err)
	}
	for _, bad := range []string{"vmess://x@1.1.1.1:1", "ss://nopass@1.1.1.1:1", "socks5://1.1.1.1", "{bad"} {
		if _, err := ParseOutbound(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}
