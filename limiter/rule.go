package limiter

import (
	"net/netip"
	"regexp"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/relay"
	log "github.com/sirupsen/logrus"
)

type relayRule struct {
	id      int
	ref     string
	matcher *relay.Matcher
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
	if relay.Bypass(ip) {
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
	l.ruleMu.Lock()
	l.DomainRules = rules
	l.ProtocolRules = rule.Protocol
	l.relayRules = relayRules
	l.ruleMu.Unlock()
	return nil
}
