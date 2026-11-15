package dispatcher

import (
	stdnet "net"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func TestAddLinkRespectsLimit(t *testing.T) {
	m := &LinkManager{links: make(map[*ManagedWriter]managedLink)}
	a, b, c := &ManagedWriter{manager: m}, &ManagedWriter{manager: m}, &ManagedWriter{manager: m}
	if !m.AddLink(a, nil, nil, "1.1.1.1", true, 2) || !m.AddLink(b, nil, nil, "1.1.1.1", true, 2) {
		t.Fatal("links under limit should be added")
	}
	if m.AddLink(c, nil, nil, "1.1.1.1", true, 2) {
		t.Fatal("link over limit should be rejected")
	}
	m.RemoveWriter(a)
	if !m.AddLink(c, nil, nil, "1.1.1.1", true, 2) {
		t.Fatal("slot should be released after a link is removed")
	}
	if !m.AddLink(&ManagedWriter{manager: m}, nil, nil, "1.1.1.1", true, 0) {
		t.Fatal("limit 0 should be unlimited")
	}
}

func TestDeviceIPIncludesStatefulQUIC(t *testing.T) {
	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	ip, counted := deviceIP(&session.Inbound{
		Source: net.UDPDestination(net.ParseAddress("1.2.3.4"), 1234),
		Conn:   c1,
	})
	if ip != "1.2.3.4" || !counted {
		t.Fatalf("stateful UDP/QUIC inbound should be counted, got ip=%q counted=%v", ip, counted)
	}

	ip, counted = deviceIP(&session.Inbound{
		Source: net.UDPDestination(net.ParseAddress("1.2.3.4"), 1234),
	})
	if ip != "1.2.3.4" || counted {
		t.Fatalf("connectionless UDP inbound should not be counted, got ip=%q counted=%v", ip, counted)
	}

	ip, counted = deviceIP(&session.Inbound{})
	if ip != "" || counted {
		t.Fatalf("missing address should safely return empty/false, got ip=%q counted=%v", ip, counted)
	}
}
