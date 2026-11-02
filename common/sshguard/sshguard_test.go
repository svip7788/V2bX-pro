package sshguard

import (
	"fmt"
	"sync"
	"sync/atomic"
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

func TestLocalTargetsExempt(t *testing.T) {
	now := time.Now()
	for _, host := range []string{"192.168.159.129", "d", "10.0.0.5", "127.0.0.1", "100.100.1.2", "fe80::1", "[fd00::1]", "nas.local", "pi.lan"} {
		for i := 0; i < 100; i++ {
			if r := check("local", host, now); r.Reject {
				t.Fatalf("local target %s rejected", host)
			}
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
	if first.Report {
		t.Fatal("first ban should not report")
	}
	second := ban(first.Until.Add(time.Minute))
	if got := second.Until.Sub(first.Until.Add(time.Minute)); got < repeatBan-time.Minute {
		t.Fatalf("repeat ban too short: %v", got)
	}
	if !second.NewBan || !second.Report {
		t.Fatalf("repeat ban should report: %+v", second)
	}
}

func TestBurstThresholdIsExclusive(t *testing.T) {
	now := time.Now()
	for i := 1; i <= burstLimit; i++ {
		if r := check("edge", "1.2.3.4", now.Add(time.Duration(i)*time.Second)); r.Reject {
			t.Fatalf("connection %d rejected, want first %d allowed", i, burstLimit)
		}
	}
	if r := check("edge", "1.2.3.4", now.Add(30*time.Second)); !r.Reject || !r.NewBan {
		t.Fatalf("connection %d should trigger ban: %+v", burstLimit+1, r)
	}
}

func TestSevereScanReportedDuringBan(t *testing.T) {
	now := time.Now()
	reports := 0
	for i := 0; i <= severeHosts+5; i++ {
		r := check("severe", fmt.Sprintf("9.9.%d.1", i), now.Add(time.Duration(i)*5*time.Second))
		if i == hostsLimit && (!r.NewBan || r.Report) {
			t.Fatalf("scan should ban without report at host %d: %+v", i+1, r)
		}
		if r.Report {
			reports++
			if i != severeHosts {
				t.Fatalf("severe report at host %d, want %d", i+1, severeHosts+1)
			}
		}
	}
	if reports != 1 {
		t.Fatalf("severe scan reported %d times, want 1", reports)
	}
}

func TestBanNotExtendedAndRepeatAfterExpiry(t *testing.T) {
	now := time.Now()
	var first Result
	for i := 0; i <= burstLimit; i++ {
		first = check("extend", "1.2.3.4", now.Add(time.Duration(i)*time.Second))
	}
	for i := 0; i < 500; i++ {
		r := check("extend", "1.2.3.4", now.Add(time.Minute+time.Duration(i)*time.Second))
		if !r.Reject || r.NewBan || !r.Until.Equal(first.Until) {
			t.Fatalf("ban changed during ban: %+v", r)
		}
	}
	if r := check("extend", "1.2.3.4", first.Until.Add(time.Second)); r.Reject {
		t.Fatal("single connection after expiry should pass")
	}
	var second Result
	for i := 0; i <= burstLimit && !second.NewBan; i++ {
		second = check("extend", "1.2.3.4", first.Until.Add(time.Duration(i+2)*time.Second))
	}
	if !second.NewBan || !second.Report || second.Until.Sub(first.Until) < repeatBan {
		t.Fatalf("second offense should be 24h ban with report: %+v", second)
	}
}

func TestSevereNotHiddenByFlooding(t *testing.T) {
	now := time.Now()
	for i := 0; i <= burstLimit; i++ {
		check("flood", "1.2.3.4", now.Add(time.Duration(i)*time.Second))
	}
	at := now.Add(time.Minute)
	reported := false
	for i := 0; i <= severeHosts; i++ {
		for j := 0; j < 300; j++ {
			at = at.Add(time.Millisecond)
			check("flood", "1.2.3.4", at)
		}
		at = at.Add(time.Millisecond)
		if r := check("flood", fmt.Sprintf("7.7.%d.1", i), at); r.Report {
			reported = true
		}
	}
	if !reported {
		t.Fatal("flooding one host hid the severe scan")
	}
}

func TestConcurrentReportOnce(t *testing.T) {
	now := time.Now()
	for i := 0; i <= burstLimit; i++ {
		check("race", "1.2.3.4", now.Add(time.Duration(i)*time.Second))
	}
	var reports atomic.Int32
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if check("race", fmt.Sprintf("6.%d.%d.1", g, i), now.Add(time.Minute)).Report {
					reports.Add(1)
				}
			}
		}(g)
	}
	wg.Wait()
	if n := reports.Load(); n != 1 {
		t.Fatalf("reported %d times, want 1", n)
	}
}

func TestExemptOnlyCodePlatforms(t *testing.T) {
	now := time.Now()
	for i := 0; i < 100; i++ {
		if r := check("codeup", "codeup.aliyun.com", now); r.Reject {
			t.Fatal("codeup rejected")
		}
	}
	var r Result
	for i := 0; i <= burstLimit; i++ {
		r = check("oss", "evil.oss-cn-hangzhou.aliyuncs.com", now.Add(time.Duration(i)*time.Second))
	}
	if !r.Reject {
		t.Fatal("aliyuncs.com hosts should not be exempt")
	}
}
