package grouppolicy

import (
	"net/netip"
	"slices"
	"strings"
)

// Flow is one initiated connection to evaluate.
type Flow struct {
	// Tenant scopes the decision.
	Tenant TenantID
	// Protocol is the flow protocol. Empty behaves as all.
	Protocol Protocol
	// Source is the initiating peer identifier.
	Source PeerID
	// Destination is the target overlay address.
	Destination string
	// DestinationPort is the target port. Zero is used for ICMP.
	DestinationPort uint16
}

// Decision is the result of evaluating a Flow.
type Decision struct {
	// Allowed reports whether the flow may pass.
	Allowed bool
	// Explicit reports whether a compiled rule matched.
	Explicit bool
	// Action is the matched action when Explicit is true.
	Action Action
	// PolicyID is the matched rule's policy.
	PolicyID PolicyID
	// RuleID is the matched rule.
	RuleID RuleID
	// Reason is a short, stable explanation of the verdict.
	Reason string
}

// Enforcer evaluates flows against a Bundle. It is safe for concurrent use.
type Enforcer struct {
	bundle *Bundle
}

// DecidePeers evaluates src -> dst using the destination peer's first
// overlay address. It is a convenience for tests and peer-level callers.
func (e *Enforcer) DecidePeers(tenant TenantID, src, dst PeerID, proto Protocol, port uint16) Decision {
	if e == nil || e.bundle == nil {
		return denyDecision("empty policy bundle")
	}
	target, ok := e.bundle.peer(tenant, dst)
	if !ok {
		return denyDecision("unknown destination peer")
	}
	if len(target.Addrs) == 0 {
		return denyDecision("destination peer has no overlay address")
	}
	return e.Decide(Flow{
		Tenant:          tenant,
		Protocol:        proto,
		Source:          src,
		Destination:     target.Addrs[0].String(),
		DestinationPort: port,
	})
}

// Decide applies the compiled rules with drop-overrides-accept and
// default-deny semantics.
func (e *Enforcer) Decide(flow Flow) Decision {
	if e == nil || e.bundle == nil {
		return denyDecision("empty policy bundle")
	}
	src, ok := e.bundle.peer(flow.Tenant, flow.Source)
	if !ok {
		// Fail closed: a principal the policy directory does not know can
		// never be allowed.
		return denyDecision("unknown source principal")
	}

	dstAddr, err := netip.ParseAddr(strings.TrimSpace(flow.Destination))
	if err != nil {
		return denyDecision("invalid destination address")
	}
	dstAddr = dstAddr.Unmap()
	proto := flow.Protocol
	if proto == "" {
		proto = ProtocolAll
	} else {
		proto = Protocol(strings.ToLower(string(proto)))
	}

	var accept *CompiledRule
	groups := e.bundle.Groups(flow.Tenant)
	for _, cg := range groups {
		for i := range cg.Rules {
			rule := &cg.Rules[i]
			if !ruleMatches(rule, src, dstAddr, proto, flow.DestinationPort) {
				continue
			}
			if rule.Action == ActionDrop {
				return Decision{
					Allowed: false, Explicit: true, Action: ActionDrop,
					PolicyID: rule.PolicyID, RuleID: rule.ID,
					Reason: "blocked by explicit drop rule",
				}
			}
			if accept == nil {
				accept = rule
			}
		}
	}

	if accept != nil {
		return Decision{
			Allowed: true, Explicit: true, Action: ActionAccept,
			PolicyID: accept.PolicyID, RuleID: accept.ID,
			Reason: "allowed by policy rule",
		}
	}
	return denyDecision("default deny: no policy grants this flow")
}

func denyDecision(reason string) Decision {
	return Decision{Allowed: false, Reason: reason}
}

func ruleMatches(rule *CompiledRule, src Peer, dst netip.Addr, proto Protocol, port uint16) bool {
	if rule.Protocol != ProtocolAll && rule.Protocol != proto {
		return false
	}
	if !portInRanges(port, rule.Ports) {
		return false
	}
	if forwardMatch(rule, src, dst) {
		return true
	}
	if rule.Bidirectional && reverseMatch(rule, src, dst) {
		return true
	}
	return false
}

func forwardMatch(rule *CompiledRule, src Peer, dst netip.Addr) bool {
	if !principalMatches(rule.Sources, src) {
		return false
	}
	return rule.Destinations.matchesDestination(dst)
}

func reverseMatch(rule *CompiledRule, src Peer, dst netip.Addr) bool {
	if !principalMatches(rule.Destinations, src) {
		return false
	}
	return rule.Sources.matchesDestination(dst)
}

func principalMatches(set MatchSet, p Peer) bool {
	if set.Any {
		return true
	}
	if slices.Contains(set.PeerIDs, p.ID) {
		return true
	}
	for _, a := range p.Addrs {
		if set.containsAddr(a) {
			return true
		}
	}
	return false
}
