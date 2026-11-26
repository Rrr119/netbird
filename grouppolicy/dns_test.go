package grouppolicy_test

import (
	"errors"
	"net/netip"
	"slices"
	"testing"

	gp "github.com/netbirdio/netbird/grouppolicy"
)

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestDNSViewIsolationAndSplitHorizon(t *testing.T) {
	cfg := &gp.Config{Tenants: []gp.Tenant{{
		ID: "t1",
		Groups: []gp.Group{
			{
				ID: "g1",
				DNS: gp.DNSConfig{
					Upstreams:     []string{"100.64.0.53:53"},
					SearchDomains: []string{"g1.internal"},
					Records: []gp.DNSRecordSpec{
						{Name: "only-g1.internal", Addrs: []netip.Addr{mustAddr("10.0.0.1")}},
						{Name: "shared.internal", Shared: true, Addrs: []netip.Addr{mustAddr("10.0.0.10")}},
						{
							Name:          "split.internal",
							Addrs:         []netip.Addr{mustAddr("10.0.0.1")},
							VisibleGroups: []gp.GroupID{"g2"},
							Answers: map[gp.GroupID][]netip.Addr{
								"g1": {mustAddr("10.0.1.1")},
								"g2": {mustAddr("10.0.2.2")},
							},
						},
					},
				},
			},
			{ID: "g2"},
			{ID: "g3"},
		},
	}}}

	bundle := compileClean(t, cfg)
	v1 := bundle.Get("t1", "g1").DNS
	v2 := bundle.Get("t1", "g2").DNS
	v3 := bundle.Get("t1", "g3").DNS

	if !slices.Contains(v1.Names(), "only-g1.internal") {
		t.Errorf("g1 should see its private name, names=%v", v1.Names())
	}
	if slices.Contains(v2.Names(), "only-g1.internal") || slices.Contains(v3.Names(), "only-g1.internal") {
		t.Errorf("private g1 name leaked: g2=%v g3=%v", v2.Names(), v3.Names())
	}
	if !slices.Contains(v2.Names(), "split.internal") || !slices.Contains(v2.Names(), "shared.internal") {
		t.Errorf("g2 should see shared and permitted split names, got %v", v2.Names())
	}
	if slices.Contains(v3.Names(), "split.internal") {
		t.Errorf("split name leaked to unauthorized g3: %v", v3.Names())
	}
	if got := v3.Names(); len(got) != 1 || got[0] != "shared.internal" {
		t.Errorf("g3 should only see shared.internal, got %v", got)
	}

	a1, err := v1.Resolve("split.internal", gp.RRTypeA)
	if err != nil || len(a1) != 1 || a1[0].String() != "10.0.1.1" {
		t.Errorf("g1 split horizon = %v,%v want 10.0.1.1", a1, err)
	}
	a2, err := v2.Resolve("split.internal", gp.RRTypeA)
	if err != nil || len(a2) != 1 || a2[0].String() != "10.0.2.2" {
		t.Errorf("g2 split horizon = %v,%v want 10.0.2.2", a2, err)
	}

	if _, err := v2.Resolve("only-g1.internal", gp.RRTypeA); !errors.Is(err, gp.ErrNoSuchName) {
		t.Errorf("hidden name should be NXDOMAIN to g2, got %v", err)
	}
	if _, err := v2.Resolve("does-not-exist.internal", gp.RRTypeA); !errors.Is(err, gp.ErrNoSuchName) {
		t.Errorf("missing name should be NXDOMAIN, got %v", err)
	}
	if _, err := v1.Resolve("only-g1.internal", gp.RRTypeAAAA); !errors.Is(err, gp.ErrNoSuchName) {
		t.Errorf("AAAA query for an A-only name should return no-such-name, got %v", err)
	}

	if ups := v1.Upstreams(); len(ups) != 1 || ups[0] != "100.64.0.53:53" {
		t.Errorf("g1 upstreams = %v", ups)
	}
	if ups := v2.Upstreams(); len(ups) != 0 {
		t.Errorf("g2 must not inherit g1 upstreams, got %v", ups)
	}
}

func TestDNSInvalidRecordIsLocatedToOwnerGroup(t *testing.T) {
	cfg := &gp.Config{Tenants: []gp.Tenant{{
		ID: "t1",
		Groups: []gp.Group{{
			ID: "g2",
			DNS: gp.DNSConfig{Records: []gp.DNSRecordSpec{
				{Name: "", Pos: gp.SourcePosition{File: "dns/g2.yaml", Line: 18}},
			}},
		}},
	}}}
	_, err := gp.CompileGroup(cfg, "t1", "g2")
	if err == nil {
		t.Fatal("invalid DNS record must fail compilation")
	}
	es, ok := gp.AsCompileErrors(err)
	if !ok {
		t.Fatalf("expected CompileErrors, got %T", err)
	}
	var found bool
	for _, ce := range es {
		if ce.Code == gp.ErrInvalidDNSRecord && ce.Location.Group == "g2" &&
			ce.Location.Field == "dns.records[0].name" && ce.Location.Pos.Line == 18 {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing located dns.records[0].name error: %v", es)
	}
}
