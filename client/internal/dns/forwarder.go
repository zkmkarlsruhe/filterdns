package dns

import (
	"strings"

	"github.com/zkm/filterdns-client/internal/config"
)

// ForwarderMatcher matches domain names against forwarder rules
type ForwarderMatcher struct {
	rules []forwarderRule
}

type forwarderRule struct {
	pattern string // The domain pattern (e.g., "ts.net", "*.internal")
	server  string // The DNS server to forward to
	isWild  bool   // Whether the pattern starts with *
}

// NewForwarderMatcher creates a new forwarder matcher
func NewForwarderMatcher(forwarders []config.Forwarder) *ForwarderMatcher {
	rules := make([]forwarderRule, 0, len(forwarders))
	for _, f := range forwarders {
		domain := strings.ToLower(strings.TrimSuffix(f.Domain, "."))
		isWild := strings.HasPrefix(domain, "*.")

		if isWild {
			domain = domain[2:] // Remove "*."
		}

		rules = append(rules, forwarderRule{
			pattern: domain,
			server:  f.Server,
			isWild:  isWild,
		})
	}
	return &ForwarderMatcher{rules: rules}
}

// Match returns the DNS server to forward to for a given domain, or "" if no match
func (m *ForwarderMatcher) Match(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	for _, rule := range m.rules {
		if rule.isWild {
			// Wildcard match: *.example.com matches foo.example.com and bar.foo.example.com
			if domain == rule.pattern || strings.HasSuffix(domain, "."+rule.pattern) {
				return rule.server
			}
		} else {
			// Exact match or suffix match
			if domain == rule.pattern || strings.HasSuffix(domain, "."+rule.pattern) {
				return rule.server
			}
		}
	}

	return ""
}
