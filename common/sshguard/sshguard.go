// Package sshguard 识别经节点做 SSH 爆破/扫描的用户，只封禁其 22 端口出站。
//
// 正常使用（登录自己的几台服务器、git over ssh）远低于阈值；
// 爆破工具会在短时间内大量重连同一目标，扫描则会连大量不同目标。
package sshguard

import (
	"strings"
	"sync"
	"time"
)

const (
	burstWindow   = time.Minute
	burstLimit    = 20 // 1 分钟内新建 22 连接数
	targetWindow  = 10 * time.Minute
	perHostLimit  = 30 // 10 分钟内连同一目标次数
	hostsLimit    = 10 // 10 分钟内不同目标数
	firstBan      = time.Hour
	repeatBan     = 24 * time.Hour
	repeatWindow  = 24 * time.Hour
	maxEntries    = 256
	sweepInterval = 5 * time.Minute
)

// Port 受保护的目标端口
const Port = 22

// exempt 代码托管平台不计数、不封禁，保证 git 正常
var exempt = []string{"github.com", "gitlab.com", "bitbucket.org", "gitee.com", "codeberg.org", "coding.net", "aliyuncs.com"}

type hit struct {
	at   time.Time
	host string
}

type state struct {
	mu       sync.Mutex
	hits     []hit
	until    time.Time
	lastBan  time.Time
	lastSeen time.Time
}

var (
	users     sync.Map // key -> *state
	sweepOnce sync.Once
)

// Result Check 的结论；NewBan 仅在本次触发封禁时为 true，用于打印一次告警
type Result struct {
	Reject bool
	NewBan bool
	Until  time.Time
	Reason string
}

func isExempt(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range exempt {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// Check 记录 key（用户）到 host:22 的一次新连接并给出是否放行
func Check(key, host string) Result {
	return check(key, host, time.Now())
}

func check(key, host string, now time.Time) Result {
	if key == "" || isExempt(host) {
		return Result{}
	}
	sweepOnce.Do(func() { go sweep() })
	v, _ := users.LoadOrStore(key, &state{})
	s := v.(*state)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastSeen = now
	if now.Before(s.until) {
		return Result{Reject: true, Until: s.until}
	}

	keep := s.hits[:0]
	for _, h := range s.hits {
		if now.Sub(h.at) < targetWindow {
			keep = append(keep, h)
		}
	}
	s.hits = append(keep, hit{at: now, host: host})
	if len(s.hits) > maxEntries {
		s.hits = s.hits[len(s.hits)-maxEntries:]
	}

	reason := evaluate(s.hits, host, now)
	if reason == "" {
		return Result{}
	}
	d := firstBan
	if !s.lastBan.IsZero() && now.Sub(s.lastBan) < repeatWindow {
		d = repeatBan
	}
	s.until = now.Add(d)
	s.lastBan = now
	s.hits = nil
	return Result{Reject: true, NewBan: true, Until: s.until, Reason: reason}
}

func evaluate(hits []hit, host string, now time.Time) string {
	burst, same := 0, 0
	hosts := make(map[string]struct{}, 16)
	for _, h := range hits {
		if now.Sub(h.at) < burstWindow {
			burst++
		}
		if h.host == host {
			same++
		}
		hosts[h.host] = struct{}{}
	}
	switch {
	case burst > burstLimit:
		return "1 分钟内新建 SSH 连接过多"
	case same > perHostLimit:
		return "10 分钟内反复连接同一 SSH 目标"
	case len(hosts) > hostsLimit:
		return "10 分钟内连接过多不同 SSH 目标"
	}
	return ""
}

func sweep() {
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for now := range t.C {
		users.Range(func(k, v any) bool {
			s := v.(*state)
			s.mu.Lock()
			idle := now.Sub(s.lastSeen) > targetWindow && now.After(s.until) && now.Sub(s.lastBan) > repeatWindow
			s.mu.Unlock()
			if idle {
				users.Delete(k)
			}
			return true
		})
	}
}
