package xray

import (
	"testing"

	"github.com/InazumaV/V2bX/common/relay"
)

func TestBuildRelayOutbound(t *testing.T) {
	for _, v := range []string{
		"ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA==@1.2.3.4:8388",
		"socks5://u:p@1.2.3.4:1080",
		"http://1.2.3.4:3128",
		`{"protocol":"freedom","settings":{"domainStrategy":"UseIPv6"}}`,
	} {
		o, err := relay.ParseOutbound(v)
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		cfg, err := buildRelayOutbound("node|relay|1", o)
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		if cfg.Tag != "node|relay|1" {
			t.Fatalf("%s: tag %q", v, cfg.Tag)
		}
	}
	o, _ := relay.ParseOutbound(`{"type":"direct"}`)
	if _, err := buildRelayOutbound("t", o); err == nil {
		t.Fatal("sing-box json should be rejected by xray")
	}
}
