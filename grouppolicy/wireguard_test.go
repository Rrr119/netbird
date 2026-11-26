package grouppolicy_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	gp "github.com/netbirdio/netbird/grouppolicy"
)

func TestWireGuardKeyRoundTrip(t *testing.T) {
	original := testKey(42)
	parsed, err := gp.ParseKey(original.String())
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	if parsed != original {
		t.Fatal("parsed key does not match original")
	}
	if _, err := gp.ParseKey("not-a-base64-key!!"); err == nil {
		t.Error("malformed key must be rejected")
	}
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	if _, err := gp.ParseKey(short); err == nil {
		t.Error("16-byte key must be rejected")
	}
}

func TestWireGuardConfigRoundTrip(t *testing.T) {
	text := fmt.Sprintf(`# existing wg-quick configuration
[Interface]
PrivateKey = %s
Address = 100.64.0.1/32, fd00::1/128
ListenPort = 51820
DNS = 100.64.0.53, example.local
MTU = 1420
PostUp = iptables -A FORWARD -j ACCEPT

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = 203.0.113.10:51820
AllowedIPs = 100.64.0.2/32
AllowedIPs = 100.64.0.3/32
PersistentKeepalive = 25
`, testKey(91), testKey(11), testKey(7))

	cfg, err := gp.ParseWireGuardConfigString(text)
	if err != nil {
		t.Fatalf("parse existing config: %v", err)
	}
	if cfg.Interface.ListenPort != 51820 || cfg.Interface.MTU != 1420 {
		t.Errorf("interface fields wrong: %+v", cfg.Interface)
	}
	if len(cfg.Interface.Addresses) != 2 {
		t.Errorf("Address should parse two prefixes, got %v", cfg.Interface.Addresses)
	}
	if len(cfg.Peers) != 1 {
		t.Fatalf("expected one peer, got %d", len(cfg.Peers))
	}
	if got := len(cfg.Peers[0].AllowedIPs); got != 2 {
		t.Errorf("repeated AllowedIPs should append, got %d", got)
	}

	rendered, err := cfg.Render()
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	cfg2, err := gp.ParseWireGuardConfigString(string(rendered))
	if err != nil {
		t.Fatalf("re-parse rendered config: %v\n%s", err, rendered)
	}
	if !reflect.DeepEqual(cfg, cfg2) {
		t.Fatalf("round trip mismatch:\noriginal=%#v\nrendered=%s\nparsed=%#v", cfg, rendered, cfg2)
	}
	if !strings.Contains(string(rendered), "[Interface]") || !strings.Contains(string(rendered), "[Peer]") {
		t.Errorf("rendered config missing sections:\n%s", rendered)
	}
}

func TestWireGuardConfigParseErrorHasLine(t *testing.T) {
	_, err := gp.ParseWireGuardConfigString("[Interface]\nListenPort = not-a-port\n")
	var ce *gp.ConfigError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *ConfigError, got %T: %v", err, err)
	}
	if ce.Line != 2 {
		t.Errorf("error line = %d, want 2", ce.Line)
	}
}

func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestBuildWireGuardConfigProjectsIsolatedAllowedIPs(t *testing.T) {
	bundle := compileClean(t, threeGroupConfig())
	cg := bundle.Get("t1", "g1")

	base := &gp.WireGuardConfig{
		Interface: gp.WireGuardInterface{
			PrivateKey: testKey(99),
			ListenPort: 51821,
			Addresses:  []netip.Prefix{prefix("100.64.1.11/32")},
		},
		Peers: []gp.WireGuardPeer{
			{
				PublicKey:           testKey(12),
				Endpoint:            "198.51.100.2:51820",
				PersistentKeepalive: 30,
				AllowedIPs:          []netip.Prefix{prefix("10.99.0.0/16")},
			},
			{
				PublicKey:  testKey(200),
				Endpoint:   "192.0.2.9:51820",
				AllowedIPs: []netip.Prefix{prefix("192.0.2.0/24")},
			},
		},
	}

	out, err := cg.BuildWireGuardConfig(base, gp.WireGuardBuildConfig{LocalPeer: "p11"})
	if err != nil {
		t.Fatalf("BuildWireGuardConfig: %v", err)
	}
	if out.Interface.ListenPort != 51821 || out.Interface.PrivateKey != testKey(99) {
		t.Error("existing interface settings must be preserved")
	}
	if len(out.Peers) != 1 {
		t.Fatalf("strict reconcile should drop the unmanaged/cross peer, got %d peers", len(out.Peers))
	}
	peer := out.Peers[0]
	if peer.PublicKey != testKey(12) || peer.Endpoint != "198.51.100.2:51820" || peer.PersistentKeepalive != 30 {
		t.Errorf("existing peer fields not preserved: %+v", peer)
	}
	if len(peer.AllowedIPs) != 1 || peer.AllowedIPs[0].String() != "100.64.1.12/32" {
		t.Errorf("AllowedIPs = %v, want exactly 100.64.1.12/32 (stale broad prefix removed)", peer.AllowedIPs)
	}

	rendered, err := out.Render()
	if err != nil {
		t.Fatalf("render projected config: %v", err)
	}
	text := string(rendered)
	if _, err := gp.ParseWireGuardConfigString(text); err != nil {
		t.Errorf("projected config must remain parseable: %v", err)
	}
	if strings.Contains(text, "100.64.2.21") || strings.Contains(text, testKey(21).String()) {
		t.Error("cross-group g2 peer must not appear in g1 WireGuard config")
	}
	if strings.Contains(text, "10.99.0.0/16") {
		t.Error("stale broad AllowedIP must be reconciled away by default")
	}

	merged, err := cg.BuildWireGuardConfig(base, gp.WireGuardBuildConfig{
		LocalPeer: "p11", MergeExistingAllowedIPs: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !containsPrefix(merged.Peers[0].AllowedIPs, "100.64.1.12/32") ||
		!containsPrefix(merged.Peers[0].AllowedIPs, "10.99.0.0/16") {
		t.Errorf("merge mode should keep policy and existing prefixes, got %v", merged.Peers[0].AllowedIPs)
	}

	preserved, err := cg.BuildWireGuardConfig(base, gp.WireGuardBuildConfig{
		LocalPeer: "p11", PreserveUnmanagedPeers: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(preserved.Peers) != 2 {
		t.Fatalf("preserve mode should keep the unmanaged peer, got %d", len(preserved.Peers))
	}
}

func TestBuildWireGuardConfigMissingKeyIsLocated(t *testing.T) {
	cfg := &gp.Config{Tenants: []gp.Tenant{{
		ID: "t1",
		Groups: []gp.Group{{ID: "g", Policies: []gp.Policy{{
			ID:    "p",
			Rules: []gp.Rule{{Sources: []string{"g"}, Destinations: []string{"g"}}},
		}}}},
		Peers: []gp.Peer{
			{ID: "p1", Groups: []gp.GroupID{"g"}, Addrs: []netip.Addr{mustAddr("10.0.0.1")}},
			{ID: "p2", Groups: []gp.GroupID{"g"}, Addrs: []netip.Addr{mustAddr("10.0.0.2")}},
		},
	}}}
	cg, err := gp.CompileGroup(cfg, "t1", "g")
	if err != nil {
		t.Fatal(err)
	}
	_, err = cg.BuildWireGuardConfig(nil, gp.WireGuardBuildConfig{LocalPeer: "p1"})
	var ce *gp.CompileError
	if !errors.As(err, &ce) || ce.Code != gp.ErrInvalidKey {
		t.Fatalf("expected located invalid_key error, got %T %v", err, err)
	}
	if ce.Location.Peer != "p2" || ce.Location.Group != "g" {
		t.Errorf("error location = %+v, want peer p2 in group g", ce.Location)
	}
}

func containsPrefix(prefixes []netip.Prefix, want string) bool {
	target := netip.MustParsePrefix(want)
	for _, p := range prefixes {
		if p == target {
			return true
		}
	}
	return false
}
