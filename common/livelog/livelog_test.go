package livelog

import (
	"sync"
	"testing"
	"time"
)

func TestWatchOpenClose(t *testing.T) {
	var mu sync.Mutex
	var got []map[string]any
	send := func(_ string, data any) {
		mu.Lock()
		got = append(got, data.(map[string]any))
		mu.Unlock()
	}
	if Enabled() {
		t.Fatal("should be disabled initially")
	}
	if c := Open("[a.com]-anytls:12", 7, "tcp", "x.com", 443, "tls", ""); c != nil {
		t.Fatal("unwatched user should not be recorded")
	}

	Watch("s1", "[a.com]-", 7, time.Minute, send)
	defer Stop("s1")
	if !Enabled() {
		t.Fatal("should be enabled")
	}
	if c := Open("[b.com]-anytls:12", 7, "tcp", "x.com", 443, "", ""); c != nil {
		t.Fatal("other panel prefix should not match")
	}
	if c := Open("[a.com]-anytls:12", 8, "tcp", "x.com", 443, "", ""); c != nil {
		t.Fatal("other uid should not match")
	}
	c := Open("[a.com]-anytls:12", 7, "tcp", "x.com", 443, "tls", "direct")
	if c == nil {
		t.Fatal("watched user should be recorded")
	}
	c.AddUp(100)
	c.AddDown(2000)
	c.Close()
	c.Close()

	sessions["s1"].flush()
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("flush count = %d", len(got))
	}
	events := got[0]["events"].([]Event)
	if len(events) != 2 || events[0].Kind != "open" || events[1].Kind != "close" {
		t.Fatalf("events = %+v", events)
	}
	if events[1].Up != 100 || events[1].Down != 2000 || events[1].Node != 12 || events[1].ID != events[0].ID {
		t.Fatalf("close event = %+v", events[1])
	}
}

func TestStopDisables(t *testing.T) {
	Watch("s2", "", 1, time.Minute, func(string, any) {})
	Stop("s2")
	if Enabled() {
		t.Fatal("should be disabled after stop")
	}
}
