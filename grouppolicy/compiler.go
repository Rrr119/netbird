package grouppolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
)

// CompiledRule is one normalized rule expanded to concrete peers and
// prefixes.
type CompiledRule struct {
	// ID is the source rule identifier.
	ID RuleID
	// PolicyID is the owning policy.
	PolicyID PolicyID
	// Name is the optional rule name.
	Name string
	// Action is accept or drop.
	Action Action
	// Protocol is the normalized protocol.
	Protocol Protocol
	// Ports are the parsed destination port ranges. Empty matches any port.
	Ports []PortRange
	// Bidirectional also matches the reply direction.
	Bidirectional bool
	// Sources is the expanded source set.
	Sources MatchSet
	// Destinations is the expanded destination set.
	Destinations MatchSet
	// Location retains the source location for decisions and diagnostics.
	Location Location
}

// AllowedPeer pairs a peer reachable through accepted rules with the
// destination prefixes that should become its WireGuard AllowedIPs.
type AllowedPeer struct {
	// Peer is the concrete remote peer.
	Peer Peer
	// AllowedIPs are the peer overlay addresses reachable by this group.
	AllowedIPs []netip.Prefix
}

// CompiledGroup is the isolated policy artifact for one group. It contains
// only the rules, DNS records and WireGuard peers that concern that group.
type CompiledGroup struct {
	// Tenant is the tenant the group belongs to.
	Tenant TenantID
	// Group is the compiled group identifier.
	Group GroupID
	// Rules are the normalized, expanded rules in source order.
	Rules []CompiledRule
	// DNS is the isolated DNS view.
	DNS *DNSView
	// AllowedPeers are the peers accepted rules can reach.
	AllowedPeers []AllowedPeer
}

// Fingerprint returns a stable digest of the compiled artifact. Two
// compilations of the same group produce the same fingerprint, so callers can
// detect whether a change to the shared document actually affected a group.
func (g *CompiledGroup) Fingerprint() string {
	h := sha256.New()
	fmt.Fprintf(h, "tenant=%s\ngroup=%s\n", g.Tenant, g.Group)
	for i, r := range g.Rules {
		fmt.Fprintf(h, "rule[%d] id=%s policy=%s action=%s proto=%s bi=%t ports=%v\n",
			i, r.ID, r.PolicyID, r.Action, r.Protocol, r.Bidirectional, r.Ports)
		writeMatchSet(h, "src", r.Sources)
		writeMatchSet(h, "dst", r.Destinations)
	}
	if g.DNS != nil {
		fmt.Fprintf(h, "dns-up=%v search=%v\n", g.DNS.Upstreams(), g.DNS.SearchDomains())
		for _, rec := range g.DNS.Records() {
			fmt.Fprintf(h, "dns=%s %s %s ttl=%d\n", rec.Name, rec.Type, rec.Addr, rec.TTL)
		}
	}
	for _, ap := range g.AllowedPeers {
		fmt.Fprintf(h, "peer=%s key=%s\n", ap.Peer.ID, ap.Peer.PublicKey.String())
		for _, p := range ap.AllowedIPs {
			fmt.Fprintf(h, "allowed=%s\n", p.String())
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeMatchSet(h io.Writer, label string, m MatchSet) {
	fmt.Fprintf(h, "%s-any=%t peers=%v\n", label, m.Any, m.PeerIDs)
	for _, p := range m.Prefixes {
		fmt.Fprintf(h, "%s-prefix=%s\n", label, p.String())
	}
}

// Bundle is the complete set of compiled groups for a document. Successful
// groups remain available even when other groups failed to compile.
type Bundle struct {
	order    []TenantID
	tenants  map[TenantID]*tenantCtx
	compiled map[TenantID]map[GroupID]*CompiledGroup
}

// Get returns the compiled group, or nil when it did not compile or does not
// exist.
func (b *Bundle) Get(tenant TenantID, group GroupID) *CompiledGroup {
	if b == nil || b.compiled[tenant] == nil {
		return nil
	}
	return b.compiled[tenant][group]
}

// Tenants returns the tenant identifiers in document order.
func (b *Bundle) Tenants() []TenantID {
	if b == nil {
		return nil
	}
	return slices.Clone(b.order)
}

// Groups returns the successfully compiled groups for tenant in order.
func (b *Bundle) Groups(tenant TenantID) []*CompiledGroup {
	if b == nil || b.tenants[tenant] == nil {
		return nil
	}
	tc := b.tenants[tenant]
	var out []*CompiledGroup
	for _, gid := range tc.groupOrder {
		if cg := b.Get(tenant, gid); cg != nil {
			out = append(out, cg)
		}
	}
	return out
}

// NewEnforcer returns a default-deny flow evaluator over the bundle.
func (b *Bundle) NewEnforcer() *Enforcer {
	return &Enforcer{bundle: b}
}

func (b *Bundle) peer(tenant TenantID, id PeerID) (Peer, bool) {
	if b == nil || b.tenants[tenant] == nil {
		return Peer{}, false
	}
	p, ok := b.tenants[tenant].peers[id]
	return p, ok
}

type tenantCtx struct {
	id         TenantID
	groups     map[GroupID]Group
	groupOrder []GroupID
	peers      map[PeerID]Peer
	members    map[GroupID][]Peer
}

type compiler struct {
	cfg     *Config
	order   []TenantID
	tenants map[TenantID]*tenantCtx
}

func newCompiler(cfg *Config) *compiler {
	c := &compiler{cfg: cfg, tenants: make(map[TenantID]*tenantCtx)}
	if cfg == nil {
		return c
	}
	for i := range cfg.Tenants {
		t := cfg.Tenants[i]
		tc, ok := c.tenants[t.ID]
		if !ok {
			tc = &tenantCtx{
				id:      t.ID,
				groups:  make(map[GroupID]Group),
				peers:   make(map[PeerID]Peer),
				members: make(map[GroupID][]Peer),
			}
			c.tenants[t.ID] = tc
			c.order = append(c.order, t.ID)
		}
		for _, g := range t.Groups {
			if _, exists := tc.groups[g.ID]; !exists {
				tc.groupOrder = append(tc.groupOrder, g.ID)
			}
			tc.groups[g.ID] = g
		}
		for _, p := range t.Peers {
			tc.peers[p.ID] = p
		}
	}
	for _, tc := range c.tenants {
		for _, p := range tc.peers {
			for _, gid := range p.Groups {
				tc.members[gid] = append(tc.members[gid], p)
			}
		}
		for gid := range tc.members {
			slices.SortFunc(tc.members[gid], func(a, b Peer) int {
				return strings.Compare(string(a.ID), string(b.ID))
			})
		}
	}
	return c
}

// Compile compiles every group in the shared document. It is an alias for
// CompileAll.
func Compile(cfg *Config) (*Bundle, error) { return CompileAll(cfg) }

// MustCompile compiles the document and panics on error. It is intended for
// examples and tests that use a known-valid configuration.
func MustCompile(cfg *Config) *Bundle {
	bundle, err := CompileAll(cfg)
	if err != nil {
		panic(err)
	}
	return bundle
}

// CompileAll compiles every tenant/group independently. A non-nil Bundle is
// always returned and contains the groups that compiled; the returned error,
// when non-nil, is a CompileErrors aggregate that locates every failure.
func CompileAll(cfg *Config) (*Bundle, error) {
	c := newCompiler(cfg)
	b := &Bundle{order: slices.Clone(c.order), tenants: c.tenants, compiled: make(map[TenantID]map[GroupID]*CompiledGroup)}

	var errs CompileErrors
	errs = append(errs, c.validateDocument()...)

	for _, tid := range c.order {
		tc := c.tenants[tid]
		seen := make(map[GroupID]struct{})
		for _, gid := range tc.groupOrder {
			if _, dup := seen[gid]; dup {
				continue
			}
			seen[gid] = struct{}{}
			cg, groupErrs := c.compileGroup(tid, gid)
			if len(groupErrs) > 0 {
				errs = append(errs, groupErrs...)
				continue
			}
			b.put(cg)
		}
	}
	return b, errs.OrNil()
}

// CompileGroup compiles exactly one group without validating or compiling
// any other group's policies. It is the isolation boundary callers can use to
// rebuild one group after an edit.
func CompileGroup(cfg *Config, tenant TenantID, group GroupID) (*CompiledGroup, error) {
	c := newCompiler(cfg)
	cg, errs := c.compileGroup(tenant, group)
	if len(errs) > 0 {
		return nil, errs.OrNil()
	}
	return cg, nil
}

func (b *Bundle) put(cg *CompiledGroup) {
	if b.compiled[cg.Tenant] == nil {
		b.compiled[cg.Tenant] = make(map[GroupID]*CompiledGroup)
	}
	b.compiled[cg.Tenant][cg.Group] = cg
}

func (c *compiler) validateDocument() CompileErrors {
	if c.cfg == nil {
		return CompileErrors{{
			Code:    ErrInvalidConfig,
			Message: "nil policy configuration",
		}}
	}
	var errs CompileErrors
	seenTenant := make(map[TenantID]int)
	for ti, t := range c.cfg.Tenants {
		tloc := Location{Tenant: t.ID}
		if t.ID == "" {
			errs = append(errs, &CompileError{Code: ErrInvalidConfig, Location: Location{Field: fmt.Sprintf("tenants[%d].id", ti)}, Message: "tenant id is required"})
		} else if prior, dup := seenTenant[t.ID]; dup {
			errs = append(errs, &CompileError{Code: ErrDuplicateID, Location: withField(tloc, fmt.Sprintf("tenants[%d].id", ti)), Message: fmt.Sprintf("tenant %q duplicated (first at index %d)", t.ID, prior)})
		} else {
			seenTenant[t.ID] = ti
		}

		knownGroups := make(map[GroupID]struct{})
		seenGroup := make(map[GroupID]struct{})
		for gi, g := range t.Groups {
			if g.ID == "" {
				errs = append(errs, &CompileError{Code: ErrInvalidConfig, Location: Location{Tenant: t.ID, Field: fmt.Sprintf("tenants[%d].groups[%d].id", ti, gi)}, Message: "group id is required"})
				continue
			}
			knownGroups[g.ID] = struct{}{}
			if _, dup := seenGroup[g.ID]; dup {
				errs = append(errs, &CompileError{Code: ErrDuplicateID, Location: Location{Tenant: t.ID, Group: g.ID, Field: fmt.Sprintf("groups[%d].id", gi)}, Message: fmt.Sprintf("group %q duplicated", g.ID)})
			}
			seenGroup[g.ID] = struct{}{}
		}

		seenPeer := make(map[PeerID]struct{})
		for pi, p := range t.Peers {
			if p.ID == "" {
				errs = append(errs, &CompileError{Code: ErrInvalidConfig, Location: Location{Tenant: t.ID, Field: fmt.Sprintf("peers[%d].id", pi)}, Message: "peer id is required"})
			} else if _, dup := seenPeer[p.ID]; dup {
				errs = append(errs, &CompileError{Code: ErrDuplicateID, Location: Location{Tenant: t.ID, Peer: p.ID, Field: fmt.Sprintf("peers[%d].id", pi)}, Message: fmt.Sprintf("peer %q duplicated", p.ID)})
			}
			seenPeer[p.ID] = struct{}{}
			for k, gid := range p.Groups {
				if _, ok := knownGroups[gid]; !ok {
					errs = append(errs, &CompileError{Code: ErrUnknownGroup, Location: Location{Tenant: t.ID, Peer: p.ID, Field: fmt.Sprintf("peers[%d].groups[%d]", pi, k)}, Message: fmt.Sprintf("peer %q references unknown group %q", p.ID, gid)})
				}
			}
		}
	}
	return errs
}

func withField(l Location, field string) Location {
	l.Field = field
	return l
}

func (c *compiler) compileGroup(tid TenantID, gid GroupID) (*CompiledGroup, CompileErrors) {
	tc, ok := c.tenants[tid]
	if !ok {
		return nil, CompileErrors{{Code: ErrInvalidConfig, Location: Location{Tenant: tid}, Message: "tenant not found"}}
	}
	group, ok := tc.groups[gid]
	if !ok {
		return nil, CompileErrors{{Code: ErrUnknownGroup, Location: Location{Tenant: tid, Group: gid}, Message: "group not found"}}
	}

	var errs CompileErrors
	dnsView, dnsErrs := buildDNSView(tc, gid)
	errs = append(errs, dnsErrs...)

	cg := &CompiledGroup{Tenant: tid, Group: gid, DNS: dnsView}
	seenPolicy := make(map[PolicyID]struct{})

	for pi, policy := range group.Policies {
		if policy.Disabled {
			continue
		}
		policyLoc := Location{Tenant: tid, Group: gid, Policy: policy.ID, Pos: policy.Pos}
		if policy.ID == "" {
			errs = append(errs, &CompileError{Code: ErrInvalidConfig, Location: withField(policyLoc, fmt.Sprintf("policies[%d].id", pi)), Message: "policy id is required"})
		} else if _, dup := seenPolicy[policy.ID]; dup {
			errs = append(errs, &CompileError{Code: ErrDuplicateID, Location: withField(policyLoc, fmt.Sprintf("policies[%d].id", pi)), Message: fmt.Sprintf("policy %q duplicated in group %q", policy.ID, gid)})
		} else {
			seenPolicy[policy.ID] = struct{}{}
		}

		seenRules := make(map[RuleID]struct{})
		for ri, rule := range policy.Rules {
			if rule.Disabled {
				continue
			}
			if rule.ID != "" {
				if _, dup := seenRules[rule.ID]; dup {
					errs = append(errs, &CompileError{
						Code:     ErrDuplicateID,
						Location: Location{Tenant: tid, Group: gid, Policy: policy.ID, Rule: rule.ID, RuleIndex: ri, Field: "id", Pos: positionFor(rule, policy)},
						Message:  fmt.Sprintf("rule %q duplicated in policy %q", rule.ID, policy.ID),
					})
				}
				seenRules[rule.ID] = struct{}{}
			}

			compiled, ruleErrs := compileRule(tc, gid, policy, rule, ri)
			if len(ruleErrs) > 0 {
				errs = append(errs, ruleErrs...)
				continue
			}
			cg.Rules = append(cg.Rules, compiled)
		}
	}

	if len(errs) > 0 {
		return nil, errs
	}
	cg.AllowedPeers = projectAllowedPeers(tc, cg.Rules)
	return cg, nil
}

func positionFor(rule Rule, policy Policy) SourcePosition {
	if rule.Pos != (SourcePosition{}) {
		return rule.Pos
	}
	return policy.Pos
}

func compileRule(tc *tenantCtx, gid GroupID, policy Policy, rule Rule, ri int) (CompiledRule, CompileErrors) {
	loc := Location{
		Tenant:    tc.id,
		Group:     gid,
		Policy:    policy.ID,
		Rule:      rule.ID,
		RuleIndex: ri,
		Pos:       positionFor(rule, policy),
	}
	var errs CompileErrors

	action := rule.Action
	if action == "" {
		action = ActionAccept
	} else {
		action = Action(strings.ToLower(string(action)))
		if action != ActionAccept && action != ActionDrop {
			errs = append(errs, &CompileError{Code: ErrInvalidAction, Location: withField(loc, "action"), Message: fmt.Sprintf("unsupported action %q", rule.Action)})
		}
	}

	proto := rule.Protocol
	if proto == "" {
		proto = ProtocolAll
	} else {
		proto = Protocol(strings.ToLower(string(proto)))
		switch proto {
		case ProtocolAll, ProtocolTCP, ProtocolUDP, ProtocolICMP:
		default:
			errs = append(errs, &CompileError{Code: ErrInvalidProtocol, Location: withField(loc, "protocol"), Message: fmt.Sprintf("unsupported protocol %q", rule.Protocol)})
		}
	}

	srcSels, srcErrs := compileSelectors(tc, loc, "sources", rule.Sources)
	errs = append(errs, srcErrs...)
	dstSels, dstErrs := compileSelectors(tc, loc, "destinations", rule.Destinations)
	errs = append(errs, dstErrs...)

	var ports []PortRange
	for i, spec := range rule.Ports {
		pr, err := ParsePortSpec(spec)
		if err != nil {
			errs = append(errs, &CompileError{
				Code:     ErrInvalidPort,
				Location: withField(loc, fmt.Sprintf("ports[%d]", i)),
				Message:  err.Error(),
				Err:      err,
			})
			continue
		}
		ports = append(ports, pr)
	}

	if len(errs) > 0 {
		return CompiledRule{}, errs
	}

	return CompiledRule{
		ID:            rule.ID,
		PolicyID:      policy.ID,
		Name:          rule.Name,
		Action:        action,
		Protocol:      proto,
		Ports:         ports,
		Bidirectional: rule.Bidirectional,
		Sources:       expandSet(srcSels, tc),
		Destinations:  expandSet(dstSels, tc),
		Location:      loc,
	}, nil
}

func compileSelectors(tc *tenantCtx, loc Location, field string, refs []string) ([]selector, CompileErrors) {
	if len(refs) == 0 {
		return nil, CompileErrors{{Code: ErrEmptySelector, Location: withField(loc, field), Message: "rule needs at least one selector"}}
	}
	var out []selector
	var errs CompileErrors
	for i, ref := range refs {
		parsed, err := parseSelectorRef(ref)
		refField := fmt.Sprintf("%s[%d]", field, i)
		if err != nil {
			code := ErrInvalidSelector
			if strings.Contains(strings.TrimSpace(ref), "/") {
				code = ErrInvalidCIDR
			}
			errs = append(errs, &CompileError{Code: code, Location: withField(loc, refField), Message: err.Error(), Err: err})
			continue
		}
		switch parsed.kind {
		case selectorGroup:
			if _, ok := tc.groups[parsed.group]; !ok {
				errs = append(errs, &CompileError{Code: ErrUnknownGroup, Location: withField(loc, refField), Message: fmt.Sprintf("unknown group %q", parsed.group)})
			}
		case selectorPeer:
			if _, ok := tc.peers[parsed.peer]; !ok {
				errs = append(errs, &CompileError{Code: ErrUnknownPeer, Location: withField(loc, refField), Message: fmt.Sprintf("unknown peer %q", parsed.peer)})
			}
		}
		out = append(out, parsed)
	}
	return out, errs
}

func expandSet(sels []selector, tc *tenantCtx) MatchSet {
	b := newMatchSetBuilder()
	for _, s := range sels {
		switch s.kind {
		case selectorAny:
			b.any()
		case selectorPrefix:
			b.addPrefix(s.prefix)
		case selectorPeer:
			if p, ok := tc.peers[s.peer]; ok {
				b.addPeer(p)
			}
		case selectorGroup:
			for _, p := range tc.members[s.group] {
				b.addPeer(p)
			}
		}
	}
	return b.build()
}

func projectAllowedPeers(tc *tenantCtx, rules []CompiledRule) []AllowedPeer {
	prefixes := make(map[PeerID]map[string]netip.Prefix)
	for _, r := range rules {
		if r.Action != ActionAccept {
			continue
		}
		for _, pid := range r.Destinations.PeerIDs {
			p, ok := tc.peers[pid]
			if !ok {
				continue
			}
			if prefixes[pid] == nil {
				prefixes[pid] = make(map[string]netip.Prefix)
			}
			for _, addr := range p.Addrs {
				pfx := addrPrefix(addr)
				prefixes[pid][pfx.String()] = pfx
			}
		}
	}

	ids := make([]PeerID, 0, len(prefixes))
	for id := range prefixes {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	out := make([]AllowedPeer, 0, len(ids))
	for _, id := range ids {
		ipList := make([]netip.Prefix, 0, len(prefixes[id]))
		for _, pfx := range prefixes[id] {
			ipList = append(ipList, pfx)
		}
		slices.SortFunc(ipList, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
		out = append(out, AllowedPeer{Peer: tc.peers[id], AllowedIPs: ipList})
	}
	return out
}
