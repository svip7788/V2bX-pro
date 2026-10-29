package sshguard

import (
	"fmt"
	"testing"
	"time"
)

func TestNormalUsageAllowed(t *testing.T) {
	now := time.Now()
	for i := 0; i < 30; i++ {
		host := fmt.Sprintf("10.0.0.%d", i%3)
		if r := check("normal", host, now.Add(time.Duration(i)*20*time.Second)); r.Reject {
			t.Fatalf("normal usage rejected at %d", i)
		}
	}
	for i := 0; i < 100; i++ {
		if r := check("git", "github.com", now); r.Reject {
			t.Fatal("github rejected")
		}
	}
}

func TestBurstBanned(t *testing.T) {
	now := time.Now()
	var r Result
	for i := 0; i <= burstLimit; i++ {
		r = check("burst", "1.2.3.4", now.Add(time.Duration(i)*time.Second))
	}
	if !r.Reject || !r.NewBan {
		t.Fatalf("burst not banned: %+v", r)
	}
	if r := check("burst", "5.6.7.8", now.Add(time.Minute)); !r.Reject || r.NewBan {
		t.Fatalf("ban not kept: %+v", r)
	}
	if r := check("burst", "ssh.github.com", now.Add(time.Minute)); r.Reject {
		t.Fatal("exempt host rejected while banned")
	}
	if r := check("burst", "1.2.3.4", now.Add(firstBan+2*time.Minute)); r.Reject {
		t.Fatal("ban not expired")
	}
}

func TestScanBanned(t *testing.T) {
	now := time.Now()
	var r Result
	for i := 0; i <= hostsLimit; i++ {
		r = check("scan", fmt.Sprintf("8.8.%d.1", i), now.Add(time.Duration(i)*10*time.Second))
	}
	if !r.NewBan {
		t.Fatalf("scan not banned: %+v", r)
	}
}

func TestRepeatBanLonger(t *testing.T) {
	now := time.Now()
	ban := func(at time.Time) Result {
		var r Result
		for i := 0; i <= burstLimit; i++ {
			r = check("repeat", "1.1.1.1", at.Add(time.Duration(i)*time.Second))
		}
		return r
	}
	first := ban(now)
	second := ban(first.Until.Add(time.Minute))
	if got := second.Until.Sub(first.Until.Add(time.Minute)); got < repeatBan-time.Minute {
		t.Fatalf("repeat ban too short: %v", got)
	}
}
