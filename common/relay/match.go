package relay

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Matcher 按行匹配目标，任一条命中即走转发：
//
//	port:22 / port:8000-8100   目标端口
//	ip:1.2.3.0/24 / 1.2.3.4     目标 IP 或网段
//	domain:x / x / *.x          域名及其子域名
//	full:x                      完整域名
//	keyword:x                   域名包含关键字
//	regexp:x                    域名正则
type Matcher struct {
	ports    [][2]uint16
	prefixes []netip.Prefix
	suffixes []string
	full     map[string]struct{}
	keywords []string
	regexps  []*regexp.Regexp
}

func NewMatcher(lines []string) (*Matcher, error) {
	m := &Matcher{full: map[string]struct{}{}}
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		kind, value, ok := strings.Cut(line, ":")
		if !ok {
			kind, value = "", line
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(kind) {
		case "port":
			r, err := parsePortRange(value)
			if err != nil {
				return nil, fmt.Errorf("invalid rule %q: %w", line, err)
			}
			m.ports = append(m.ports, r)
		case "ip", "cidr":
			p, err := parsePrefix(value)
			if err != nil {
				return nil, fmt.Errorf("invalid rule %q: %w", line, err)
			}
			m.prefixes = append(m.prefixes, p)
		case "full":
			m.full[strings.ToLower(value)] = struct{}{}
		case "keyword":
			m.keywords = append(m.keywords, strings.ToLower(value))
		case "regexp":
			r, err := regexp.Compile(value)
			if err != nil {
				return nil, fmt.Errorf("invalid rule %q: %w", line, err)
			}
			m.regexps = append(m.regexps, r)
		case "domain":
			m.addSuffix(value)
		default:
			// IPv6 地址含冒号，Cut 会误切
			if p, err := parsePrefix(line); err == nil {
				m.prefixes = append(m.prefixes, p)
			} else {
				m.addSuffix(line)
			}
		}
	}
	return m, nil
}

func (m *Matcher) addSuffix(v string) {
	v = strings.TrimPrefix(strings.ToLower(v), "*.")
	v = strings.Trim(v, ".")
	if v != "" {
		m.suffixes = append(m.suffixes, v)
	}
}

func (m *Matcher) Empty() bool {
	return len(m.ports) == 0 && len(m.prefixes) == 0 && len(m.suffixes) == 0 &&
		len(m.full) == 0 && len(m.keywords) == 0 && len(m.regexps) == 0
}

// Match host 为域名（可空），ip 为目标 IP（可无效）
func (m *Matcher) Match(host string, ip netip.Addr, port uint16) bool {
	for _, r := range m.ports {
		if port >= r[0] && port <= r[1] {
			return true
		}
	}
	if ip.IsValid() {
		ip = ip.Unmap()
		for _, p := range m.prefixes {
			if p.Contains(ip) {
				return true
			}
		}
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return false
	}
	if _, ok := m.full[host]; ok {
		return true
	}
	for _, s := range m.suffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	for _, k := range m.keywords {
		if strings.Contains(host, k) {
			return true
		}
	}
	for _, r := range m.regexps {
		if r.MatchString(host) {
			return true
		}
	}
	return false
}

// Bypass 内网/本机地址永不转发，避免借中继机访问其内网
func Bypass(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// BypassHost localhost 到中继机上会解析成中继机自身
func BypassHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

func parsePortRange(v string) ([2]uint16, error) {
	lo, hi, isRange := strings.Cut(v, "-")
	a, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
	if err != nil {
		return [2]uint16{}, err
	}
	b := a
	if isRange {
		if b, err = strconv.ParseUint(strings.TrimSpace(hi), 10, 16); err != nil {
			return [2]uint16{}, err
		}
	}
	if a == 0 || b < a {
		return [2]uint16{}, fmt.Errorf("bad port range")
	}
	return [2]uint16{uint16(a), uint16(b)}, nil
}

func parsePrefix(v string) (netip.Prefix, error) {
	if strings.Contains(v, "/") {
		p, err := netip.ParsePrefix(v)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(v)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}
