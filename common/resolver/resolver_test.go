package resolver

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func answer(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	q := req.Question[0]
	switch {
	case q.Name == "v4.test." && q.Qtype == dns.TypeA:
		resp.Answer = append(resp.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("1.2.3.4")})
	case q.Name == "v6.test." && q.Qtype == dns.TypeAAAA:
		resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::1")})
	case q.Name == "nx.test.":
		resp.Rcode = dns.RcodeNameError
	}
	return resp
}

func TestNew(t *testing.T) {
	ok := []string{"8.8.8.8", "8.8.8.8:5353", "udp://8.8.8.8", "tcp://1.1.1.1:53", "tls://dns.google", "https://dns.google/dns-query", "https+local://doh.example.com", "2001:4860:4860::8888"}
	for _, s := range ok {
		if _, err := New(s); err != nil {
			t.Errorf("New(%q) = %v", s, err)
		}
	}
	for _, s := range []string{"quic+local://dns.adguard.com", "https://", "tls://"} {
		if _, err := New(s); err == nil {
			t.Errorf("New(%q) expected error", s)
		}
	}
}

func TestUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) { _ = w.WriteMsg(answer(req)) })}
	go srv.ActivateAndServe()
	defer srv.Shutdown()

	r, err := New(pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	check(t, r)
}

func TestDoH(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, hr *http.Request) {
		body, _ := io.ReadAll(hr.Body)
		req := new(dns.Msg)
		if err := req.Unpack(body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		out, _ := answer(req).Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	defer ts.Close()

	r, err := New(ts.URL + "/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	r.http = ts.Client()
	check(t, r)
}

func check(t *testing.T, r *Resolver) {
	t.Helper()
	ctx := context.Background()
	if a, err := r.Lookup(ctx, "V4.test."); err != nil || a != netip.MustParseAddr("1.2.3.4") {
		t.Errorf("v4 = %v %v", a, err)
	}
	if a, err := r.Lookup(ctx, "v6.test"); err != nil || a != netip.MustParseAddr("2001:db8::1") {
		t.Errorf("v6 = %v %v", a, err)
	}
	if _, err := r.Lookup(ctx, "nx.test"); err == nil {
		t.Error("nx expected error")
	}
	if _, ok := r.cache["v4.test"]; !ok {
		t.Error("v4 not cached")
	}
}
