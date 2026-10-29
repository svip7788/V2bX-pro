package limiter

import (
	"testing"

	"github.com/InazumaV/V2bX/api/panel"
)

func TestMatchDNS(t *testing.T) {
	l := &Limiter{}
	err := l.UpdateRule(&panel.Rules{DNS: []panel.DNSRule{
		{Id: 1, Match: []string{"netflix.com", "full:nflxvideo.net"}, Server: "https://dns.example.com/dns-query"},
		{Id: 2, Match: []string{"bad.com"}, Server: "quic+local://x"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if r := l.MatchDNS("www.netflix.com"); r == nil || r.String() != "https://dns.example.com/dns-query" {
		t.Errorf("www.netflix.com = %v", r)
	}
	if l.MatchDNS("nflxvideo.net") == nil {
		t.Error("full match missed")
	}
	for _, host := range []string{"a.nflxvideo.net", "bad.com", "1.2.3.4", "localhost", ""} {
		if r := l.MatchDNS(host); r != nil {
			t.Errorf("%q should not match, got %v", host, r)
		}
	}
}
