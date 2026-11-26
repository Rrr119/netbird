package grouppolicy_test

import (
	"net/netip"
	"strings"
	"testing"

	gp "github.com/netbirdio/netbird/grouppolicy"
)

func testKey(seed byte) gp.Key {
	var k gp.Key
	for i := range k {
		k[i] = seed + byte(i*7)
	}
	return k
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func peer(id gp.PeerID, ip string, keySeed byte, groups ...gp.GroupID) gp.Peer {
	return gp.Peer{
		ID:        id,
		Groups:    groups,
		Addrs:     []netip.Addr{addr(ip)},
		PublicKey: testKey(keySeed),
	}
}

func intraPolicy(group gp.GroupID) gp.Policy {
	return gp.Policy{
		ID:   gp.PolicyID("pol-" + string(group)),
		Name: "intra group only",
		Rules: []gp.Rule{{
			ID:           gp.RuleID("allow-" + string(group) + "-intra"),
			Action:       gp.ActionAccept,
			Protocol:     gp.ProtocolAll,
			Sources:      []string{string(group)},
			Destinations: []string{string(group)},
		}},
	}
}

// threeGroupConfig builds the acceptance topology: three isolated groups,
// each with two peers and a single intra-group accept-all policy.
func threeGroupConfig() *gp.Config {
	return &gp.Config{Tenants: []gp.Tenant{{
		ID: "t1",
		Groups: []gp.Group{
			{ID: "g1", Policies: []gp.Policy{intraPolicy("g1")}},
			{ID: "g2", Policies: []gp.Policy{intraPolicy("g2")}},
			{ID: "g3", Policies: []gp.Policy{intraPolicy("g3")}},
		},
		Peers: []gp.Peer{
			peer("p11", "100.64.1.11", 11, "g1"),
			peer("p12", "100.64.1.12", 12, "g1"),
			peer("p21", "100.64.2.21", 21, "g2"),
			peer("p22", "100.64.2.22", 22, "g2"),
			peer("p31", "100.64.3.31", 31, "g3"),
			peer("p32", "100.64.3.32", 32, "g3"),
		},
	}}}
}

var peerGroup = map[gp.PeerID]gp.GroupID{
	"p11": "g1", "p12": "g1",
	"p21": "g2", "p22": "g2",
	"p31": "g3", "p32": "g3",
}

func allPeers() []gp.PeerID {
	return []gp.PeerID{"p11", "p12", "p21", "p22", "p31", "p32"}
}

func compileClean(t *testing.T, cfg *gp.Config) *gp.Bundle {
	t.Helper()
	bundle, err := gp.CompileAll(cfg)
	if err != nil {
		t.Fatalf("CompileAll returned unexpected error: %v", err)
	}
	if bundle == nil {
		t.Fatal("CompileAll returned nil bundle")
	}
	return bundle
}

// TestThreeGroups_CrossGroupBlocked_IntraAllowed is the headline acceptance
// check: under three group policies every cross-group direction is denied
// while every distinct pair inside a group is allowed.
func TestThreeGroups_CrossGroupBlocked_IntraAllowed(t *testing.T) {
	bundle := compileClean(t, threeGroupConfig())
	enforcer := bundle.NewEnforcer()

	peers := allPeers()
	var allowedIntra, blockedCross int
	for _, src := range peers {
		for _, dst := range peers {
			if src == dst {
				continue
			}
			decision := enforcer.DecidePeers("t1", src, dst, gp.ProtocolTCP, 443)
			sameGroup := peerGroup[src] == peerGroup[dst]
			if sameGroup {
				if !decision.Allowed {
					t.Errorf("intra-group %s -> %s must be allowed, got %q", src, dst, decision.Reason)
					continue
				}
				if decision.RuleID != gp.RuleID("allow-"+string(peerGroup[src])+"-intra") {
					t.Errorf("%s -> %s matched rule %q, want intra rule", src, dst, decision.RuleID)
				}
				allowedIntra++
			} else {
				if decision.Allowed {
					t.Errorf("cross-group %s(%s) -> %s(%s) must be blocked",
						src, peerGroup[src], dst, peerGroup[dst])
					continue
				}
				if decision.Explicit {
					t.Errorf("cross-group %s -> %s must default-deny, matched %q", src, dst, decision.RuleID)
				}
				if !strings.Contains(decision.Reason, "default deny") {
					t.Errorf("cross-group %s -> %s reason = %q, want default deny", src, dst, decision.Reason)
				}
				blockedCross++
			}
		}
	}

	if allowedIntra != 6 {
		t.Errorf("allowed intra-group directions = %d, want 6", allowedIntra)
	}
	if blockedCross != 24 {
		t.Errorf("blocked cross-group directions = %d, want 24", blockedCross)
	}
}

func TestThreeGroups_ICMPAndZeroPort(t *testing.T) {
	bundle := compileClean(t, threeGroupConfig())
	enforcer := bundle.NewEnforcer()

	if d := enforcer.DecidePeers("t1", "p21", "p22", gp.ProtocolICMP, 0); !d.Allowed {
		t.Errorf("ICMP inside g2 should pass: %s", d.Reason)
	}
	if d := enforcer.DecidePeers("t1", "p21", "p31", gp.ProtocolICMP, 0); d.Allowed {
		t.Error("ICMP g2 -> g3 must be blocked")
	}
}

func TestUnknownPrincipalFailsClosed(t *testing.T) {
	bundle := compileClean(t, threeGroupConfig())
	enforcer := bundle.NewEnforcer()

	if d := enforcer.DecidePeers("t1", "ghost", "p11", gp.ProtocolTCP, 443); d.Allowed {
		t.Error("unknown source peer must be denied")
	}
	if d := enforcer.DecidePeers("t1", "p11", "ghost", gp.ProtocolTCP, 443); d.Allowed {
		t.Error("unknown destination peer must be denied")
	}
	if d := enforcer.Decide(gp.Flow{Tenant: "t1", Source: "p11", Destination: "not-an-ip"}); d.Allowed {
		t.Error("invalid destination address must be denied")
	}
}

// TestPortAndProtocolScoping proves rules narrow traffic by port and protocol
// rather than allowing everything between the selected groups.
func TestPortAndProtocolScoping(t *testing.T) {
	cfg := &gp.Config{Tenants: []gp.Tenant{{
		ID: "t1",
		Groups: []gp.Group{
			{ID: "clients"},
			{ID: "web", Policies: []gp.Policy{{
				ID: "web-policy",
				Rules: []gp.Rule{{
					ID: "https-only", Action: gp.ActionAccept, Protocol: gp.ProtocolTCP,
					Sources: []string{"clients"}, Destinations: []string{"web"},
					Ports: []string{"443"},
				}},
			}}},
		},
		Peers: []gp.Peer{
			peer("c1", "100.64.9.1", 1, "clients"),
			peer("w1", "100.64.9.2", 2, "web"),
		},
	}}}
	enforcer := compileClean(t, cfg).NewEnforcer()

	if d := enforcer.DecidePeers("t1", "c1", "w1", gp.ProtocolTCP, 443); !d.Allowed {
		t.Errorf("tcp/443 should pass: %s", d.Reason)
	}
	if d := enforcer.DecidePeers("t1", "c1", "w1", gp.ProtocolTCP, 8443); d.Allowed {
		t.Error("tcp/8443 must be blocked by the 443-only rule")
	}
	if d := enforcer.DecidePeers("t1", "c1", "w1", gp.ProtocolUDP, 443); d.Allowed {
		t.Error("udp/443 must be blocked by the tcp-only rule")
	}
	if d := enforcer.DecidePeers("t1", "c1", "w1", gp.ProtocolICMP, 0); d.Allowed {
		t.Error("icmp must be blocked by the tcp-only rule")
	}
}

// TestCompileError_Localization checks that a bad rule identifies the exact
// tenant, group, policy, rule index, field and source position.
func TestCompileError_Localization(t *testing.T) {
	cfg := threeGroupConfig()
	g1 := &cfg.Tenants[0].Groups[0]
	g1.Policies[0].Rules = append(g1.Policies[0].Rules, gp.Rule{
		ID:           "r-bad",
		Action:       gp.ActionAccept,
		Protocol:     gp.ProtocolTCP,
		Sources:      []string{"g1"},
		Destinations: []string{"ghost-group"},
		Ports:        []string{"70000"},
		Pos:          gp.SourcePosition{File: "policies/g1.json", Line: 7, Column: 3},
	})

	_, err := gp.CompileGroup(cfg, "t1", "g1")
	if err == nil {
		t.Fatal("CompileGroup must fail for the invalid rule")
	}
	es, ok := gp.AsCompileErrors(err)
	if !ok {
		t.Fatalf("error must be a CompileErrors aggregate, got %T: %v", err, err)
	}

	var unknownGroup *gp.CompileError
	var badPort *gp.CompileError
	for _, ce := range es {
		switch ce.Code {
		case gp.ErrUnknownGroup:
			if ce.Location.Field == "destinations[0]" {
				unknownGroup = ce
			}
		case gp.ErrInvalidPort:
			badPort = ce
		}
	}
	if unknownGroup == nil {
		t.Fatalf("expected located unknown_group error, got %v", es)
	}
	if badPort == nil {
		t.Fatalf("expected located invalid_port error, got %v", es)
	}

	loc := unknownGroup.Location
	if loc.Tenant != "t1" || loc.Group != "g1" || loc.Policy != "pol-g1" {
		t.Errorf("context = %q/%q/%q, want t1/g1/pol-g1", loc.Tenant, loc.Group, loc.Policy)
	}
	if loc.Rule != "r-bad" || loc.RuleIndex != 1 {
		t.Errorf("rule locator = id %q index %d, want r-bad/1", loc.Rule, loc.RuleIndex)
	}
	if loc.Pos.File != "policies/g1.json" || loc.Pos.Line != 7 || loc.Pos.Column != 3 {
		t.Errorf("source position = %v, want policies/g1.json:7:3", loc.Pos)
	}

	msg := err.Error()
	for _, want := range []string{
		"unknown group", "tenant=t1", "group=g1", "policy=pol-g1",
		"rule=r-bad", "rule_index=1", "field=destinations[0]", "at=policies/g1.json:7:3",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message %q does not contain %q", msg, want)
		}
	}
}

// TestPerGroupCompilationIsolation proves a broken group neither corrupts nor
// blocks the healthy groups, and that compiling a healthy group directly is
// unaffected by the broken document section.
func TestPerGroupCompilationIsolation(t *testing.T) {
	good := threeGroupConfig()
	goodBundle := compileClean(t, good)
	fpG2 := goodBundle.Get("t1", "g2").Fingerprint()
	fpG3 := goodBundle.Get("t1", "g3").Fingerprint()

	bad := threeGroupConfig()
	bad.Tenants[0].Groups[0].Policies[0].Rules = append(
		bad.Tenants[0].Groups[0].Policies[0].Rules,
		gp.Rule{
			ID: "r-broken", Sources: []string{"g1"},
			Destinations: []string{"missing"}, Ports: []string{"nope"},
		},
	)

	bundle, err := gp.CompileAll(bad)
	if err == nil {
		t.Fatal("CompileAll must report the broken g1 rule")
	}
	if _, ok := gp.AsCompileErrors(err); !ok {
		t.Fatalf("expected CompileErrors, got %T", err)
	}
	if bundle == nil {
		t.Fatal("bundle must still be returned for healthy groups")
	}
	if bundle.Get("t1", "g1") != nil {
		t.Error("failed group g1 must not publish an artifact")
	}

	g2 := bundle.Get("t1", "g2")
	g3 := bundle.Get("t1", "g3")
	if g2 == nil || g3 == nil {
		t.Fatalf("healthy groups missing: g2=%v g3=%v", g2 != nil, g3 != nil)
	}
	if g2.Fingerprint() != fpG2 {
		t.Error("g2 artifact changed after editing and breaking g1")
	}
	if g3.Fingerprint() != fpG3 {
		t.Error("g3 artifact changed after editing and breaking g1")
	}

	directG2, directErr := gp.CompileGroup(bad, "t1", "g2")
	if directErr != nil {
		t.Fatalf("isolated CompileGroup(g2) must not see g1 errors: %v", directErr)
	}
	if directG2.Fingerprint() != fpG2 {
		t.Error("direct g2 compile differs from clean baseline")
	}

	enforcer := bundle.NewEnforcer()
	if d := enforcer.DecidePeers("t1", "p21", "p22", gp.ProtocolTCP, 22); !d.Allowed {
		t.Errorf("g2 intra traffic must still pass: %s", d.Reason)
	}
	if d := enforcer.DecidePeers("t1", "p21", "p31", gp.ProtocolTCP, 22); d.Allowed {
		t.Error("g2 -> g3 cross traffic must stay blocked")
	}
	if d := enforcer.DecidePeers("t1", "p11", "p21", gp.ProtocolTCP, 22); d.Allowed {
		t.Error("g1 has no compiled allow rule after failure, so g1 -> g2 must stay blocked")
	}
}

func TestDuplicatePolicyAndRuleAreLocated(t *testing.T) {
	cfg := &gp.Config{Tenants: []gp.Tenant{{
		ID: "t1",
		Groups: []gp.Group{{ID: "g1", Policies: []gp.Policy{
			{ID: "p1", Rules: []gp.Rule{
				{ID: "same", Sources: []string{"*"}, Destinations: []string{"*"}},
				{ID: "same", Sources: []string{"*"}, Destinations: []string{"*"}},
			}},
			{ID: "p1"},
		}}},
	}}}
	_, err := gp.CompileGroup(cfg, "t1", "g1")
	if err == nil {
		t.Fatal("duplicate policy and rule ids must fail compilation")
	}
	es, ok := gp.AsCompileErrors(err)
	if !ok || len(es) < 2 {
		t.Fatalf("expected at least two located errors, got %v", err)
	}
	var codes []gp.ErrCode
	for _, ce := range es {
		codes = append(codes, ce.Code)
	}
	if !containsCode(codes, gp.ErrDuplicateID) {
		t.Fatalf("expected duplicate_id in %v", codes)
	}
}

func containsCode(codes []gp.ErrCode, want gp.ErrCode) bool {
	for _, c := range codes {
		if c == want {
			return true
		}
	}
	return false
}
