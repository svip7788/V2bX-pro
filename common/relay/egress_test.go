package relay

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// fakeFirewall 只模拟 V2BX_RELAY 链和 OUTPUT 跳转
type fakeFirewall struct {
	chain bool
	jump  bool
	rules []string
	adds  int
}

func (f *fakeFirewall) run(bin string, args ...string) error {
	rule := strings.Join(args[2:], " ")
	switch {
	case args[0] == "-L":
		if !f.chain {
			return errors.New("no chain")
		}
	case args[0] == "-N":
		f.chain = true
	case args[0] == "-C" && args[1] == "OUTPUT":
		if !f.jump {
			return errors.New("no jump")
		}
	case args[0] == "-I":
		f.jump = true
	case args[0] == "-C":
		if !slices.Contains(f.rules, rule) {
			return errors.New("no rule")
		}
	case args[0] == "-A":
		f.rules = append(f.rules, rule)
		f.adds++
	case args[0] == "-D":
		f.rules = slices.DeleteFunc(f.rules, func(r string) bool { return r == rule })
	}
	return nil
}

func (f *fakeFirewall) list(string) (string, error) {
	var b strings.Builder
	for _, r := range f.rules {
		b.WriteString("-A " + egressChain + " " + r + "\n")
	}
	return b.String(), nil
}

func setupFake(t *testing.T) *fakeFirewall {
	f := &fakeFirewall{}
	oldEnabled, oldHas, oldRun, oldList, oldLookup := egressEnabled, hasFirewall, runFirewall, listFirewall, lookupHost
	egressEnabled = true
	hasFirewall = func(bin string) bool { return bin == "iptables" }
	runFirewall = f.run
	listFirewall = f.list
	lookupHost = func(host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("5.6.7.8")}, nil
	}
	egressOwners = map[string][]endpoint{}
	egressApplied = map[string][]string{}
	t.Cleanup(func() {
		egressEnabled, hasFirewall, runFirewall, listFirewall, lookupHost = oldEnabled, oldHas, oldRun, oldList, oldLookup
		egressOwners = map[string][]endpoint{}
		egressApplied = map[string][]string{}
	})
	return f
}

func mustOut(t *testing.T, v string) *Outbound {
	o, err := ParseOutbound(v)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestAllowEgressLifecycle(t *testing.T) {
	f := setupFake(t)
	socks := mustOut(t, "socks5://u:p@1.2.3.4:31080")

	AllowEgress("node1", []*Outbound{socks, mustOut(t, "direct")})
	if !f.chain || !f.jump || len(f.rules) != 2 {
		t.Fatalf("chain=%v jump=%v rules=%v", f.chain, f.jump, f.rules)
	}

	AllowEgress("node1", []*Outbound{socks})
	if f.adds != 2 {
		t.Fatalf("re-sync should not re-add existing rules, adds=%d", f.adds)
	}

	f.rules = nil
	syncEgressLocked()
	if len(f.rules) != 2 {
		t.Fatalf("externally flushed rules should be restored: %v", f.rules)
	}

	AllowEgress("node2", []*Outbound{mustOut(t, "ss://aes-128-gcm:pw@relay.example.com:8388"), socks})
	if len(f.rules) != 4 {
		t.Fatalf("want 4 rules (shared socks deduped), got %v", f.rules)
	}

	AllowEgress("node2", nil)
	if len(f.rules) != 2 || !slices.Contains(f.rules, "-d 1.2.3.4 -p tcp --dport 31080 -j ACCEPT") {
		t.Fatalf("node2 revoke must keep node1 socks rule: %v", f.rules)
	}
}

func TestAllowEgressCleansStaleAfterRestart(t *testing.T) {
	f := setupFake(t)
	f.chain, f.jump = true, true
	f.rules = []string{
		"-d 9.9.9.9/32 -p tcp --dport 1080 -j ACCEPT",
		"-d 9.9.9.9/32 -p udp --dport 1080 -j ACCEPT",
	}
	// 真实 iptables -S 输出带 /32，删除时按同样写法匹配
	runFirewall = func(bin string, args ...string) error {
		for i, a := range args {
			if a == "9.9.9.9" {
				args[i] = "9.9.9.9/32"
			}
		}
		return f.run(bin, args...)
	}
	AllowEgress("node1", []*Outbound{mustOut(t, "socks5://1.2.3.4:31080")})
	for _, r := range f.rules {
		if strings.Contains(r, "9.9.9.9") {
			t.Fatalf("stale rule not removed: %v", f.rules)
		}
	}
	if len(f.rules) != 2 {
		t.Fatalf("rules=%v", f.rules)
	}
}

func TestOutboundEndpointFromJSON(t *testing.T) {
	cases := map[string]endpoint{
		`{"protocol":"socks","settings":{"servers":[{"address":"a.com","port":1080}]}}`: {"a.com", 1080},
		`{"protocol":"vless","settings":{"vnext":[{"address":"b.com","port":443}]}}`:    {"b.com", 443},
		`{"type":"shadowsocks","server":"c.com","server_port":8388}`:                    {"c.com", 8388},
	}
	for raw, want := range cases {
		got, ok := mustOut(t, raw).endpoint()
		if !ok || got != want {
			t.Fatalf("%s: got %v %v", raw, got, ok)
		}
	}
	if _, ok := mustOut(t, "direct").endpoint(); ok {
		t.Fatal("ref outbound has no endpoint")
	}
}
