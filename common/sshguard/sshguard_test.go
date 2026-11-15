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
	// 公网目标：单目标 1 分钟 50 次、10 分钟 200 次（如 AI 连续运维执行命令）应放行
	for i := 0; i < 50; i++ {
		if r := check("ai-burst", "47.88.1.10", now.Add(time.Duration(i)*time.Second)); r.Reject {
			t.Fatalf("normal public burst rejected at %d: %+v", i, r)
		}
	}
	for i := 0; i < 200; i++ {
		if r := check("ai-10m", "47.88.1.11", now.Add(time.Duration(i)*3*time.Second)); r.Reject {
			t.Fatalf("normal public 10m usage rejected at %d: %+v", i, r)
		}
	}
	// 多台自有服务器正常轮流连接也应放行
	for i := 0; i < 60; i++ {
		host := fmt.Sprintf("47.88.2.%d", i%3+1)
		if r := check("multi-own", host, now.Add(time.Duration(i)*5*time.Second)); r.Reject {
			t.Fatalf("normal multi-server usage rejected at %d: %+v", i, r)
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

func TestSingleHostCooldownOnly(t *testing.T) {
	now := time.Now()
	var r Result
	for i := 0; i <= perHostBurstLimit; i++ {
		r = check("single-cool", "1.2.3.4", now.Add(time.Duration(i)*500*time.Millisecond))
	}
	if !r.Reject || !r.NewBan || r.Report {
		t.Fatalf("single-host burst should trigger cooldown without report: %+v", r)
	}
	if got := r.Until.Sub(now.Add(time.Duration(perHostBurstLimit) * 500 * time.Millisecond)); got != hostCooldown {
		t.Fatalf("unexpected cooldown duration: %v, want %v", got, hostCooldown)
	}
	// 冷却只针对单目标，其他公网服务器 22 端口不受影响
	if r := check("single-cool", "5.6.7.8", now.Add(time.Minute)); r.Reject {
		t.Fatalf("other host rejected during single-host cooldown: %+v", r)
	}
	// 冷却期内重复请求不延长冷却
	if r2 := check("single-cool", "1.2.3.4", now.Add(time.Minute)); !r2.Reject || r2.NewBan || !r2.Until.Equal(r.Until) {
		t.Fatalf("cooldown changed during cooldown: %+v", r2)
	}
	// 冷却结束后自动恢复，且再次触发不会升级成 24 小时封禁或上报
	after := r.Until.Add(time.Second)
	if r := check("single-cool", "1.2.3.4", after); r.Reject {
		t.Fatalf("cooldown not expired: %+v", r)
	}
	var second Result
	for i := 0; i <= perHostBurstLimit && !second.NewBan; i++ {
		second = check("single-cool", "1.2.3.4", after.Add(time.Duration(i+1)*500*time.Millisecond))
	}
	if !second.NewBan || second.Report || second.Until.Sub(after) > hostCooldown+time.Minute {
		t.Fatalf("single-host repeat should stay short cooldown without report: %+v", second)
	}
}

func TestScanBanned(t *testing.T) {
	now := time.Now()
	var r Result
	for i := 0; i <= hostsLimit; i++ {
		r = check("scan", fmt.Sprintf("8.8.%d.1", i), now.Add(time.Duration(i)*10*time.Second))
	}
	if !r.Reject || !r.NewBan || r.Report {
		t.Fatalf("first scan should ban 1h without report: %+v", r)
	}
	if r := check("scan", "9.9.9.9", now.Add(time.Duration(hostsLimit)*10*time.Second+time.Second)); !r.Reject || r.NewBan {
		t.Fatalf("ban not kept across hosts: %+v", r)
	}
	if r := check("scan", "ssh.github.com", now.Add(time.Minute)); r.Reject {
		t.Fatal("exempt host rejected while banned")
	}
	if r := check("scan", "1.2.3.4", r.Until.Add(time.Second)); r.Reject {
		t.Fatal("ban not expired")
	}
}

func TestScanBurstBanned(t *testing.T) {
	now := time.Now()
	var r Result
	for i := 0; i <= scanBurstLimit; i++ {
		r = check("scan-burst", fmt.Sprintf("4.4.%d.1", i%scanBurstMinHosts), now.Add(time.Duration(i)*200*time.Millisecond))
	}
	if !r.Reject || !r.NewBan || r.Report {
		t.Fatalf("multi-host burst should trigger 1h ban without report: %+v", r)
	}
}

func TestRepeatScanReported(t *testing.T) {
	now := time.Now()
	ban := func(at time.Time) Result {
		var r Result
		for i := 0; i <= hostsLimit; i++ {
			r = check("multi", fmt.Sprintf("5.5.%d.1", i), at.Add(time.Duration(i)*time.Second))
		}
		return r
	}
	first := ban(now)
	if !first.NewBan || first.Report {
		t.Fatalf("first ban should not report: %+v", first)
	}
	second := ban(first.Until.Add(time.Minute))
	if !second.NewBan || !second.Report {
		t.Fatalf("multi-target repeat ban should report: %+v", second)
	}
	if got := second.Until.Sub(first.Until.Add(time.Minute)); got < repeatBan-time.Minute {
		t.Fatalf("repeat ban too short: %v", got)
	}
}

// 隧道脚本断线后每 3 秒重连同一台服务器，长时间运行也不能封 24 小时或上报封号
func TestReconnectLoopNeverReported(t *testing.T) {
	now := time.Now()
	for i := 0; i < 3*3600/3; i++ {
		if r := check("tunnel", "76.13.181.87", now.Add(time.Duration(i)*3*time.Second)); r.Report {
			t.Fatalf("reconnect loop reported at attempt %d: %+v", i, r)
		}
	}
}

func TestPerHostThresholdIsExclusive(t *testing.T) {
	now := time.Now()
	for i := 1; i <= perHostBurstLimit; i++ {
		if r := check("edge", "1.2.3.4", now.Add(time.Duration(i)*500*time.Millisecond)); r.Reject {
			t.Fatalf("connection %d rejected, want first %d allowed", i, perHostBurstLimit)
		}
	}
	if r := check("edge", "1.2.3.4", now.Add(40*time.Second)); !r.Reject || !r.NewBan {
		t.Fatalf("connection %d should trigger cooldown: %+v", perHostBurstLimit+1, r)
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
	for i := 0; i <= hostsLimit; i++ {
		first = check("extend", fmt.Sprintf("3.3.%d.1", i), now.Add(time.Duration(i)*time.Second))
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
	for i := 0; i <= scanBurstLimit && !second.NewBan; i++ {
		second = check("extend", fmt.Sprintf("3.4.%d.1", i%scanBurstMinHosts), first.Until.Add(time.Duration(i+2)*200*time.Millisecond))
	}
	if !second.NewBan || second.Report || second.Until.Sub(first.Until) < repeatBan {
		t.Fatalf("3-target second offense should be 24h ban without report: %+v", second)
	}
}

func TestSevereNotHiddenByFlooding(t *testing.T) {
	now := time.Now()
	for i := 0; i <= hostsLimit; i++ {
		check("flood", fmt.Sprintf("2.2.%d.1", i), now.Add(time.Duration(i)*time.Second))
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
	for i := 0; i <= hostsLimit; i++ {
		check("race", fmt.Sprintf("6.0.%d.1", i), now.Add(time.Duration(i)*time.Second))
	}
	var reports atomic.Int32
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if check("race", fmt.Sprintf("6.%d.%d.1", g+1, i), now.Add(time.Minute)).Report {
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
	for i := 0; i <= perHostBurstLimit; i++ {
		r = check("oss", "evil.oss-cn-hangzhou.aliyuncs.com", now.Add(time.Duration(i)*500*time.Millisecond))
	}
	if !r.Reject {
		t.Fatal("aliyuncs.com hosts should not be exempt")
	}
}

func TestHostNormalization(t *testing.T) {
	now := time.Now()
	for i := 0; i < perHostBurstLimit/2; i++ {
		if r := check("norm", "SSH.Example.COM.", now.Add(time.Duration(i)*500*time.Millisecond)); r.Reject {
			t.Fatalf("unexpected reject at %d", i)
		}
	}
	for i := perHostBurstLimit / 2; i < perHostBurstLimit; i++ {
		if r := check("norm", "ssh.example.com", now.Add(time.Duration(i)*500*time.Millisecond)); r.Reject {
			t.Fatalf("unexpected reject at %d", i)
		}
	}
	if r := check("norm", "ssh.example.com", now.Add(40*time.Second)); !r.Reject || !r.NewBan {
		t.Fatalf("expected normalized host to trigger cooldown: %+v", r)
	}
}
