package sing

import (
	"context"
	"testing"

	"github.com/InazumaV/V2bX/common/relay"
	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
)

func TestBuildRelayOutbound(t *testing.T) {
	b := &Sing{ctx: box.Context(context.Background(), include.InboundRegistry(), include.OutboundRegistry(), include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry())}
	cases := map[string]string{
		"ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA==@1.2.3.4:8388": C.TypeShadowsocks,
		"socks5://u:p@1.2.3.4:1080":                                          C.TypeSOCKS,
		"http://1.2.3.4:3128":                                                C.TypeHTTP,
		`{"type":"direct","domain_strategy":"ipv6_only"}`:                    C.TypeDirect,
	}
	for v, want := range cases {
		o, err := relay.ParseOutbound(v)
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		typ, opts, err := b.buildRelayOutbound(o)
		if err != nil || typ != want || opts == nil {
			t.Fatalf("%s: type=%q opts=%v err=%v", v, typ, opts, err)
		}
	}
	o, _ := relay.ParseOutbound(`{"protocol":"freedom"}`)
	if _, _, err := b.buildRelayOutbound(o); err == nil {
		t.Fatal("xray json should be rejected by sing-box")
	}
}
