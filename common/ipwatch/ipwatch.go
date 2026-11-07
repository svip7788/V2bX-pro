// Package ipwatch 统计用户经节点访问「查询出口 IP」类目标（如 ip.sb、国内回连地址）的次数，
// 10 分钟内达到阈值即上报面板记录（只记录不封号）。这类访问会让国内服务拿到节点 IP，是节点被墙的常见诱因。
package ipwatch

import (
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	window        = 10 * time.Minute
	sweepInterval = 5 * time.Minute
)

// Matcher 一组监控目标：域名按后缀匹配，IP / CIDR 按地址匹配
type Matcher struct {
	domains   []string
	prefixes  []netip.Prefix
	threshold int
}

// New targets 为空或阈值非正时返回 nil，表示关闭
func New(targets []string, threshold int) *Matcher {
	if threshold <= 0 {
		return nil
	}
	m := &Matcher{threshold: threshold}
	for _, t := range targets {
		t = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(t), "."))
		if t == "" {
			continue
		}
		if p, err := netip.ParsePrefix(t); err == nil {
			m.prefixes = append(m.prefixes, p.Masked())
		} else if ip, err := netip.ParseAddr(t); err == nil {
			m.prefixes = append(m.prefixes, netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen()))
		} else {
			m.domains = append(m.domains, strings.TrimPrefix(t, "*."))
		}
	}
	if len(m.domains) == 0 && len(m.prefixes) == 0 {
		return nil
	}
	return m
}

// Match host 为域名或 IP
func (m *Matcher) Match(host string) bool {
	if m == nil || host == "" {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		for _, p := range m.prefixes {
			if p.Contains(ip) {
				return true
			}
		}
		return false
	}
	for _, d := range m.domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

type state struct {
	mu   sync.Mutex
	hits []time.Time
	last time.Time
}

var (
	matchers  sync.Map // tag -> *Matcher
	users     sync.Map // key -> *state
	sweepOnce sync.Once
)

// Set 设置节点的监控目标，nil 为关闭
func Set(tag string, m *Matcher) {
	if m == nil {
		matchers.Delete(tag)
		return
	}
	matchers.Store(tag, m)
}

// Enabled 节点是否开启监控，热路径上先判断，避免无谓查用户
func Enabled(tag string) bool {
	_, ok := matchers.Load(tag)
	return ok
}

// Check 记录 key（用户）对 hosts（实际目标与嗅探域名）的一次新连接；
// 10 分钟内命中次数达到阈值时返回命中的目标与次数，随后重新计数
func Check(tag, key string, hosts ...string) (target string, count int) {
	v, ok := matchers.Load(tag)
	if !ok || key == "" {
		return "", 0
	}
	m := v.(*Matcher)
	for _, h := range hosts {
		if m.Match(h) {
			target = h
			break
		}
	}
	if target == "" {
		return "", 0
	}
	return target, hit(key, m.threshold, time.Now())
}

func hit(key string, threshold int, now time.Time) int {
	sweepOnce.Do(func() { go sweep() })
	v, _ := users.LoadOrStore(key, &state{})
	s := v.(*state)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = now
	keep := s.hits[:0]
	for _, t := range s.hits {
		if now.Sub(t) < window {
			keep = append(keep, t)
		}
	}
	s.hits = append(keep, now)
	if n := len(s.hits); n >= threshold {
		s.hits = nil
		return n
	}
	return 0
}

func sweep() {
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for now := range t.C {
		users.Range(func(k, v any) bool {
			s := v.(*state)
			s.mu.Lock()
			idle := now.Sub(s.last) > window
			s.mu.Unlock()
			if idle {
				users.Delete(k)
			}
			return true
		})
	}
}
