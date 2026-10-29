package limiter

import (
	"net/netip"
	"regexp"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/relay"
	"github.com/InazumaV/V2bX/common/resolver"
	log "github.com/sirupsen/logrus"
)

type relayRule struct {
	id      int
	ref     string
	matcher *relay.Matcher
}

type dnsRule struct {
	matcher  *relay.Matcher
	resolver *resolver.Resolver
}

func (l *Limiter) CheckDomainRule(destination string) (reject bool) {
	l.ruleMu.RLock()
	rules := l.DomainRules
	l.ruleMu.RUnlock()
	for i := range rules {
		if rules[i].MatchString(destination) {
			reject = true
			break
		}
	}
	return
}

func (l *Limiter) CheckProtocolRule(protocol string) (reject bool) {
	l.ruleMu.RLock()
	rules := l.ProtocolRules
	l.ruleMu.RUnlock()
	for i := range rules {
		if rules[i] == protocol {
			reject = true
			break
		}
	}
	return
}

// MatchRelay 返回命中规则的出站 tag，空串表示不转发
func (l *Limiter) MatchRelay(nodeTag string, host string, ip netip.Addr, port uint16) string {
	if relay.Bypass(ip) || relay.BypassHost(host) {
		return ""
	}
	l.ruleMu.RLock()
	rules := l.relayRules
	l.ruleMu.RUnlock()
	for i := range rules {
		if rules[i].matcher.Match(host, ip, port) {
			if rules[i].ref != "" {
				return rules[i].ref
			}
			return relay.Tag(nodeTag, rules[i].id)
		}
	}
	return ""
}

// MatchDNS 返回命中 dns 路由组的解析器，nil 表示用默认解析
func (l *Limiter) MatchDNS(host string) *resolver.Resolver {
	if host == "" || relay.BypassHost(host) {
		return nil
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	l.ruleMu.RLock()
	rules := l.dnsRules
	l.ruleMu.RUnlock()
	for i := range rules {
		if rules[i].matcher.Match(host, netip.Addr{}, 0) {
			return rules[i].resolver
		}
	}
	return nil
}

// AllowBitTorrent 面板为该节点放行 BT 时为 true
func (l *Limiter) AllowBitTorrent() bool {
	return l.allowBT.Load()
}

func (l *Limiter) UpdateRule(rule *panel.Rules) error {
	rules := make([]*regexp.Regexp, 0, len(rule.Regexp))
	for i := range rule.Regexp {
		r, err := regexp.Compile(rule.Regexp[i])
		if err != nil {
			continue
		}
		rules = append(rules, r)
	}
	relayRules := make([]relayRule, 0, len(rule.Relay))
	for _, r := range rule.Relay {
		o, err := relay.ParseOutbound(r.Outbound)
		if err != nil {
			log.WithFields(log.Fields{"route": r.Id, "err": err}).Warn("Skip invalid relay outbound")
			continue
		}
		m, err := relay.NewMatcher(r.Match)
		if err != nil {
			log.WithFields(log.Fields{"route": r.Id, "err": err}).Warn("Skip invalid relay rule")
			continue
		}
		if !m.Empty() {
			relayRules = append(relayRules, relayRule{id: r.Id, ref: o.Ref, matcher: m})
		}
	}
	dnsRules := make([]dnsRule, 0, len(rule.DNS))
	for _, r := range rule.DNS {
		res, err := resolver.Get(r.Server)
		if err != nil {
			log.WithFields(log.Fields{"route": r.Id, "err": err}).Warn("Skip invalid dns server")
			continue
		}
		m, err := relay.NewMatcher(r.Match)
		if err != nil {
			log.WithFields(log.Fields{"route": r.Id, "err": err}).Warn("Skip invalid dns rule")
			continue
		}
		if !m.Empty() {
			dnsRules = append(dnsRules, dnsRule{matcher: m, resolver: res})
		}
	}
	l.allowBT.Store(rule.AllowBT)
	l.ruleMu.Lock()
	l.DomainRules = rules
	l.ProtocolRules = rule.Protocol
	l.relayRules = relayRules
	l.dnsRules = dnsRules
	l.ruleMu.Unlock()
	return nil
}
