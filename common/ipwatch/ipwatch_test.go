package ipwatch

import (
	"testing"
	"time"
)

func TestMatch(t *testing.T) {
	m := New([]string{"ip.sb", "*.ipify.org", "8.138.80.41", "10.0.0.0/8", " "}, 3)
	for host, want := range map[string]bool{
		"api-ipv4.ip.sb":     true,
		"ip.sb":              true,
		"API.IPIFY.ORG.":     true,
		"notip.sb":           false,
		"8.138.80.41":        true,
		"::ffff:8.138.80.41": true,
		"8.138.80.42":        false,
		"10.2.3.4":           true,
		"example.com":        false,
		"":                   false,
	} {
		if got := m.Match(host); got != want {
			t.Errorf("Match(%q) = %v, want %v", host, got, want)
		}
	}
	if New(nil, 3) != nil || New([]string{"ip.sb"}, 0) != nil {
		t.Fatal("empty targets or non-positive threshold should disable")
	}
}

func TestCheckThresholdAndWindow(t *testing.T) {
	Set("n1", New([]string{"ip.sb"}, 3))
	defer Set("n1", nil)
	if _, n := Check("n1", "u", "example.com", ""); n != 0 {
		t.Fatal("unmatched host must not count")
	}
	if _, n := Check("n2", "u", "ip.sb"); n != 0 || Enabled("n2") {
		t.Fatal("node without matcher must not count")
	}
	for i := 1; i <= 2; i++ {
		if _, n := Check("n1", "u", "1.1.1.1", "api.ip.sb"); n != 0 {
			t.Fatalf("hit %d reported early", i)
		}
	}
	if target, n := Check("n1", "u", "1.1.1.1", "api.ip.sb"); n != 3 || target != "api.ip.sb" {
		t.Fatalf("third hit should report, got %q %d", target, n)
	}
	if _, n := Check("n1", "u", "ip.sb"); n != 0 {
		t.Fatal("count should restart after report")
	}

	now := time.Now()
	hit("w", 2, now.Add(-window))
	if n := hit("w", 2, now); n != 0 {
		t.Fatal("hits outside window must expire")
	}
}
