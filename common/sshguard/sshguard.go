// Package sshguard 识别经节点做 SSH 爆破/扫描的用户，区分单目标高频与多目标扫描：
//
//   - 正常使用（AI 工具、运维脚本、CI 等对少数服务器高频建连）放宽阈值；
//   - 仅单目标超出频率限制时，只对该目标冷却 2 分钟，不封整个 22 端口、不升级 24 小时、不上报面板；
//   - 多目标扫描（10 分钟超过 hostsLimit 个不同目标，或短时多目标并发爆破）才封全用户 22 端口：
//     首次封 1 小时不上报，24 小时内再次命中且涉及至少 reportMinHosts 个不同目标，或 10 分钟内
//     连接超过 severeHosts 个不同目标时才上报面板封号。
package sshguard

import (
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	burstWindow        = time.Minute
	perHostBurstLimit  = 60              // 1 分钟内连同一目标上限，超出仅对该目标短冷却
	scanBurstLimit     = 120             // 1 分钟内多目标新建 22 连接上限
	scanBurstMinHosts  = 3               // 触发全局突发封禁的最少不同目标数
	targetWindow       = 10 * time.Minute
	perHostLimit       = 300             // 10 分钟内连同一目标上限，超出仅对该目标短冷却
	hostsLimit         = 15              // 10 分钟内不同目标数上限
	severeHosts        = 30              // 10 分钟内不同目标数超过即上报，封禁期间继续统计
	reportMinHosts     = 5               // 再次命中时窗口内不同目标数达到才上报
	hostCooldown       = 2 * time.Minute // 单目标高频冷却时间
	firstBan           = time.Hour
	repeatBan          = 24 * time.Hour
	repeatWindow       = 24 * time.Hour
	maxEntries         = 2048
	sweepInterval      = 5 * time.Minute
)

// Port 受保护的目标端口
const Port = 22

// exempt 代码托管平台不计数、不封禁，保证 git 正常
var exempt = []string{"github.com", "gitlab.com", "bitbucket.org", "gitee.com", "codeberg.org", "coding.net", "codeup.aliyun.com"}

// cgnat 100.64.0.0/10，Tailscale 等组网常用
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

type hit struct {
	at   time.Time
	host string
}

type state struct {
	mu            sync.Mutex
	hits          []hit
	hostCooldowns map[string]time.Time // 单目标短冷却截止时间
	until         time.Time
	lastBan       time.Time
	lastSeen      time.Time
	reported      bool                 // 本轮封禁已上报
	banHosts      map[string]time.Time // 封禁期间尝试的不同目标，最多 severeHosts+1 个，上报后释放
}

var (
	users     sync.Map // key -> *state
	sweepOnce sync.Once
)

// Result Check 的结论；NewBan 仅在本次触发封禁时为 true，用于打印一次告警；
// Report 为 true 时需上报面板，每轮封禁最多一次
type Result struct {
	Reject bool
	NewBan bool
	Report bool
	Until  time.Time
	Reason string
}

// localSuffix 局域网主机名后缀，客户端全局/TUN 模式误把内网 ssh 送进代理时会出现
var localSuffix = []string{".local", ".lan", ".internal", ".localdomain", ".home", ".home.arpa", ".corp"}

func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().String()
	}
	return host
}

// isExempt 代码平台、内网地址、本地主机名不可能是被爆破的外部目标，不计数
func isExempt(host string) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() ||
			cgnat.Contains(ip)
	}
	if !strings.Contains(host, ".") {
		return true
	}
	for _, s := range localSuffix {
		if strings.HasSuffix(host, s) {
			return true
		}
	}
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
	host = normalizeHost(host)
	if key == "" || host == "" || isExempt(host) {
		return Result{}
	}
	sweepOnce.Do(func() { go sweep() })
	v, _ := users.LoadOrStore(key, &state{})
	s := v.(*state)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastSeen = now

	// 封禁期间连接全部被拒，不进 hits，只统计不同目标数用于判断是否上报，也不延长封禁
	if now.Before(s.until) {
		r := Result{Reject: true, Until: s.until}
		if s.reported {
			return r
		}
		for h, at := range s.banHosts {
			if now.Sub(at) >= targetWindow {
				delete(s.banHosts, h)
			}
		}
		s.banHosts[host] = now
		if len(s.banHosts) > severeHosts {
			s.reported, s.banHosts = true, nil
			r.Report, r.Reason = true, severeReason
		}
		return r
	}

	for h, until := range s.hostCooldowns {
		if !now.Before(until) {
			delete(s.hostCooldowns, h)
		}
	}
	if until, ok := s.hostCooldowns[host]; ok {
		return Result{Reject: true, Until: until}
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
	burst, sameBurst, same, hosts := count(s.hits, host, now)

	// 优先检查多目标扫描或跨多目标的高频爆破
	reason := ""
	switch {
	case hosts > hostsLimit:
		reason = "10 分钟内连接过多不同 SSH 目标"
	case burst > scanBurstLimit && hosts >= scanBurstMinHosts:
		reason = "1 分钟内多目标新建 SSH 连接过多"
	}
	if reason != "" {
		repeat := !s.lastBan.IsZero() && now.Sub(s.lastBan) < repeatWindow
		d := firstBan
		if repeat {
			d = repeatBan
			reason = "24 小时内再次触发：" + reason
		}
		report := repeat && hosts >= reportMinHosts
		s.until = now.Add(d)
		s.lastBan = now
		s.reported = report
		s.hits = nil
		s.hostCooldowns = nil
		s.banHosts = nil
		if !report {
			s.banHosts = make(map[string]time.Time, severeHosts+1)
			for _, h := range keep {
				s.banHosts[h.host] = h.at
			}
			s.banHosts[host] = now
		}
		return Result{Reject: true, NewBan: true, Report: report, Until: s.until, Reason: reason}
	}

	// 单目标高频只冷却该目标，不封全用户 22 端口，不计入累犯，不上报面板
	var cooldownReason string
	switch {
	case sameBurst > perHostBurstLimit:
		cooldownReason = "1 分钟内连接同一 SSH 目标过于频繁，临时冷却"
	case same > perHostLimit:
		cooldownReason = "10 分钟内连接同一 SSH 目标过于频繁，临时冷却"
	}
	if cooldownReason != "" {
		if s.hostCooldowns == nil {
			s.hostCooldowns = make(map[string]time.Time)
		}
		until := now.Add(hostCooldown)
		s.hostCooldowns[host] = until
		// 保留一条当前目标记录维持 hosts 计数，清理同目标历史以免冷却结束立刻再触发
		filtered := s.hits[:0]
		for _, h := range s.hits {
			if h.host != host {
				filtered = append(filtered, h)
			}
		}
		s.hits = append(filtered, hit{at: now, host: host})
		return Result{Reject: true, NewBan: true, Until: until, Reason: cooldownReason}
	}

	return Result{}
}

const severeReason = "10 分钟内扫描过多不同 SSH 目标"

func count(hits []hit, host string, now time.Time) (burst, sameBurst, same, hosts int) {
	seen := make(map[string]struct{}, 16)
	for _, h := range hits {
		inBurst := now.Sub(h.at) < burstWindow
		if inBurst {
			burst++
		}
		if h.host == host {
			same++
			if inBurst {
				sameBurst++
			}
		}
		seen[h.host] = struct{}{}
	}
	return burst, sameBurst, same, len(seen)
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
