package grouppolicy_test

import (
	"errors"
	"fmt"

	gp "github.com/netbirdio/netbird/grouppolicy"
)

func ExampleEnforcer_DecidePeers_threeGroups() {
	group := func(id gp.GroupID) gp.Group {
		return gp.Group{ID: id, Policies: []gp.Policy{{
			ID: gp.PolicyID("p-" + string(id)),
			Rules: []gp.Rule{{
				ID: "intra", Sources: []string{string(id)}, Destinations: []string{string(id)},
			}},
		}}}
	}
	cfg := &gp.Config{Tenants: []gp.Tenant{{
		ID:     "t1",
		Groups: []gp.Group{group("g1"), group("g2"), group("g3")},
		Peers: []gp.Peer{
			peer("p1", "100.64.0.1", 1, "g1"),
			peer("p2", "100.64.0.2", 2, "g2"),
			peer("p3", "100.64.0.3", 3, "g3"),
		},
	}}}

	enforcer := gp.MustCompile(cfg).NewEnforcer()
	for _, src := range []gp.PeerID{"p1", "p2", "p3"} {
		var row []string
		for _, dst := range []gp.PeerID{"p1", "p2", "p3"} {
			if enforcer.DecidePeers("t1", src, dst, gp.ProtocolTCP, 443).Allowed {
				row = append(row, "allow")
			} else {
				row = append(row, "deny ")
			}
		}
		fmt.Printf("%s: %v\n", src, row)
	}
	// Output:
	// p1: [allow deny  deny ]
	// p2: [deny  allow deny ]
	// p3: [deny  deny  allow]
}

func ExampleCompileGroup_errorLocation() {
	cfg := &gp.Config{Tenants: []gp.Tenant{{
		ID: "t1",
		Groups: []gp.Group{{
			ID: "g1",
			Policies: []gp.Policy{{
				ID: "pol",
				Rules: []gp.Rule{{
					ID: "r1", Sources: []string{"g1"}, Destinations: []string{"missing"},
					Pos: gp.SourcePosition{File: "policies/g1.json", Line: 9, Column: 2},
				}},
			}},
		}},
	}}}

	_, err := gp.CompileGroup(cfg, "t1", "g1")
	var es gp.CompileErrors
	if errors.As(err, &es) && len(es) > 0 {
		ce := es[0]
		fmt.Println(ce.Code)
		fmt.Printf("%s/%s/%s index=%d field=%s\n",
			ce.Location.Tenant, ce.Location.Group, ce.Location.Policy,
			ce.Location.RuleIndex, ce.Location.Field)
		fmt.Println(ce.Location.Pos.String())
	}
	// Output:
	// unknown_group
	// t1/g1/pol index=0 field=destinations[0]
	// policies/g1.json:9:2
}
