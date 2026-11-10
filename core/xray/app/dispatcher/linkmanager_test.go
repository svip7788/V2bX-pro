package dispatcher

import "testing"

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
