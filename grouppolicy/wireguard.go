package grouppolicy

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Key is a 32-byte WireGuard key. Its string form is the canonical base64
// encoding used in wg and wg-quick configuration files.
type Key [32]byte

// ParseKey parses a base64 encoded 32-byte WireGuard key.
func ParseKey(s string) (Key, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return Key{}, fmt.Errorf("decode WireGuard key: %w", err)
	}
	if len(raw) != 32 {
		return Key{}, fmt.Errorf("WireGuard key must be 32 bytes, got %d", len(raw))
	}
	var k Key
	copy(k[:], raw)
	return k, nil
}

// String returns the base64 encoded key.
func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// IsZero reports whether the key is the all-zero key.
func (k Key) IsZero() bool {
	var zero Key
	return k == zero
}

// INIKeyValue is an unrecognized configuration key preserved across a
// parse/render round trip.
type INIKeyValue struct {
	// Key is the original INI key.
	Key string
	// Value is the raw INI value.
	Value string
}

// WireGuardInterface is the [Interface] section of a WireGuard configuration.
type WireGuardInterface struct {
	// PrivateKey is the interface private key.
	PrivateKey Key
	// Addresses are the wg-quick Address prefixes.
	Addresses []netip.Prefix
	// ListenPort is the UDP listen port.
	ListenPort uint16
	// DNS holds DNS servers and search entries from the DNS key.
	DNS []string
	// MTU is the interface MTU.
	MTU int
	// Table is the optional routing table setting.
	Table string
	// Extra preserves unrecognized interface keys.
	Extra []INIKeyValue
}

// WireGuardPeer is one [Peer] section.
type WireGuardPeer struct {
	// PublicKey is the peer public key.
	PublicKey Key
	// PresharedKey is the optional pre-shared key.
	PresharedKey Key
	// Endpoint is the optional host:port endpoint.
	Endpoint string
	// AllowedIPs are the cryptokey routing prefixes.
	AllowedIPs []netip.Prefix
	// PersistentKeepalive is the keepalive interval in seconds.
	PersistentKeepalive uint16
	// Extra preserves unrecognized peer keys.
	Extra []INIKeyValue
}

// WireGuardConfig is a parsed WireGuard/wg-quick configuration.
type WireGuardConfig struct {
	// Interface is the single [Interface] section.
	Interface WireGuardInterface
	// Peers are the [Peer] sections in file order.
	Peers []WireGuardPeer
}

// ConfigError describes a malformed WireGuard configuration line.
type ConfigError struct {
	// Line is the 1-based line number.
	Line int
	// Reason describes the parse failure.
	Reason string
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("wireguard config line %d: %s", e.Line, e.Reason)
}

// ParseWireGuardConfigString parses WireGuard INI text.
func ParseWireGuardConfigString(text string) (*WireGuardConfig, error) {
	return ParseWireGuardConfig(strings.NewReader(text))
}

// ParseWireGuardConfig parses the canonical WireGuard INI format used by wg
// and wg-quick. Repeated AllowedIPs and Address keys are appended.
func ParseWireGuardConfig(r io.Reader) (*WireGuardConfig, error) {
	cfg := &WireGuardConfig{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	section := ""
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		line := stripComment(raw)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch name {
			case "interface":
				section = "interface"
			case "peer":
				cfg.Peers = append(cfg.Peers, WireGuardPeer{})
				section = "peer"
			default:
				return nil, &ConfigError{Line: lineNo, Reason: "unknown section [" + name + "]"}
			}
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, &ConfigError{Line: lineNo, Reason: "expected key = value"}
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" {
			return nil, &ConfigError{Line: lineNo, Reason: "empty key"}
		}

		switch section {
		case "interface":
			if err := parseInterfaceKey(&cfg.Interface, key, value); err != nil {
				return nil, &ConfigError{Line: lineNo, Reason: err.Error()}
			}
		case "peer":
			if len(cfg.Peers) == 0 {
				return nil, &ConfigError{Line: lineNo, Reason: "key outside of [Peer] section"}
			}
			peer := &cfg.Peers[len(cfg.Peers)-1]
			if err := parsePeerKey(peer, key, value); err != nil {
				return nil, &ConfigError{Line: lineNo, Reason: err.Error()}
			}
		default:
			return nil, &ConfigError{Line: lineNo, Reason: "key before any section"}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func stripComment(line string) string {
	if i := strings.Index(line, "#"); i >= 0 {
		return line[:i]
	}
	return line
}

func keyEqual(key, want string) bool { return strings.EqualFold(key, want) }

func parseInterfaceKey(iface *WireGuardInterface, key, value string) error {
	switch {
	case keyEqual(key, "PrivateKey"):
		k, err := ParseKey(value)
		if err != nil {
			return err
		}
		iface.PrivateKey = k
	case keyEqual(key, "Address"):
		prefixes, err := parsePrefixList(value)
		if err != nil {
			return err
		}
		iface.Addresses = append(iface.Addresses, prefixes...)
	case keyEqual(key, "ListenPort"):
		p, err := parseUint16Value(value)
		if err != nil {
			return fmt.Errorf("invalid ListenPort: %w", err)
		}
		iface.ListenPort = p
	case keyEqual(key, "DNS"):
		iface.DNS = append(iface.DNS, splitCSV(value)...)
	case keyEqual(key, "MTU"):
		mtu, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return fmt.Errorf("invalid MTU %q", value)
		}
		iface.MTU = mtu
	case keyEqual(key, "Table"):
		iface.Table = value
	default:
		iface.Extra = append(iface.Extra, INIKeyValue{Key: key, Value: value})
	}
	return nil
}

func parsePeerKey(peer *WireGuardPeer, key, value string) error {
	switch {
	case keyEqual(key, "PublicKey"):
		k, err := ParseKey(value)
		if err != nil {
			return err
		}
		peer.PublicKey = k
	case keyEqual(key, "PresharedKey"):
		k, err := ParseKey(value)
		if err != nil {
			return err
		}
		peer.PresharedKey = k
	case keyEqual(key, "Endpoint"):
		peer.Endpoint = value
	case keyEqual(key, "AllowedIPs"):
		prefixes, err := parsePrefixList(value)
		if err != nil {
			return err
		}
		peer.AllowedIPs = append(peer.AllowedIPs, prefixes...)
	case keyEqual(key, "PersistentKeepalive"):
		trimmed := strings.TrimSpace(value)
		if strings.EqualFold(trimmed, "off") || trimmed == "" {
			peer.PersistentKeepalive = 0
			return nil
		}
		v, err := parseUint16Value(trimmed)
		if err != nil {
			return fmt.Errorf("invalid PersistentKeepalive: %w", err)
		}
		peer.PersistentKeepalive = v
	default:
		peer.Extra = append(peer.Extra, INIKeyValue{Key: key, Value: value})
	}
	return nil
}

func parseUint16Value(value string) (uint16, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(v), nil
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parsePrefixList(value string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range splitCSV(value) {
		if strings.Contains(item, "/") {
			p, err := netip.ParsePrefix(item)
			if err != nil {
				return nil, fmt.Errorf("invalid prefix %q: %w", item, err)
			}
			out = append(out, netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked())
			continue
		}
		addr, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("invalid address or prefix %q", item)
		}
		out = append(out, addrPrefix(addr))
	}
	return out, nil
}

// Render serializes the configuration to canonical WireGuard INI text.
func (c *WireGuardConfig) Render() ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("nil WireGuard configuration")
	}
	var b strings.Builder
	b.WriteString("[Interface]\n")
	if !c.Interface.PrivateKey.IsZero() {
		fmt.Fprintf(&b, "PrivateKey = %s\n", c.Interface.PrivateKey.String())
	}
	if prefixes := canonicalPrefixes(c.Interface.Addresses); len(prefixes) > 0 {
		writePrefixLine(&b, "Address", prefixes)
	}
	if c.Interface.ListenPort > 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", c.Interface.ListenPort)
	}
	if len(c.Interface.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(c.Interface.DNS, ", "))
	}
	if c.Interface.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", c.Interface.MTU)
	}
	if c.Interface.Table != "" {
		fmt.Fprintf(&b, "Table = %s\n", c.Interface.Table)
	}
	for _, ex := range c.Interface.Extra {
		fmt.Fprintf(&b, "%s = %s\n", ex.Key, ex.Value)
	}

	for i := range c.Peers {
		peer := c.Peers[i]
		if peer.PublicKey.IsZero() {
			return nil, fmt.Errorf("peer #%d is missing a public key", i)
		}
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", peer.PublicKey.String())
		if !peer.PresharedKey.IsZero() {
			fmt.Fprintf(&b, "PresharedKey = %s\n", peer.PresharedKey.String())
		}
		if peer.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", peer.Endpoint)
		}
		if prefixes := canonicalPrefixes(peer.AllowedIPs); len(prefixes) > 0 {
			writePrefixLine(&b, "AllowedIPs", prefixes)
		}
		if peer.PersistentKeepalive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", peer.PersistentKeepalive)
		}
		for _, ex := range peer.Extra {
			fmt.Fprintf(&b, "%s = %s\n", ex.Key, ex.Value)
		}
	}
	return []byte(b.String()), nil
}

func writePrefixLine(b *strings.Builder, key string, prefixes []netip.Prefix) {
	values := make([]string, len(prefixes))
	for i, p := range prefixes {
		values[i] = p.String()
	}
	fmt.Fprintf(b, "%s = %s\n", key, strings.Join(values, ", "))
}

func canonicalPrefixes(in []netip.Prefix) []netip.Prefix {
	seen := make(map[string]netip.Prefix, len(in))
	for _, p := range in {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked()
		seen[p.String()] = p
	}
	out := make([]netip.Prefix, 0, len(seen))
	for _, p := range seen {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	return out
}

// WireGuardBuildConfig controls how a compiled group is projected onto an
// existing WireGuard configuration.
type WireGuardBuildConfig struct {
	// LocalPeer is the peer receiving the rendered configuration; its own
	// /32 is never placed in a [Peer] section.
	LocalPeer PeerID
	// PreserveUnmanagedPeers keeps [Peer] sections absent from the compiled
	// policy instead of reconciling them away. The default removes them so
	// cross-group peers cannot keep a tunnel.
	PreserveUnmanagedPeers bool
	// MergeExistingAllowedIPs unions pre-existing AllowedIPs with the
	// policy-derived ones. The default replaces them so stale broad prefixes
	// cannot survive a policy change.
	MergeExistingAllowedIPs bool
}

// BuildWireGuardConfig projects the compiled group onto WireGuard
// configuration. When base is non-nil its interface settings and matching
// peer endpoint, key and keepalive fields are preserved, making the result
// compatible with an existing configuration.
func (g *CompiledGroup) BuildWireGuardConfig(base *WireGuardConfig, cfg WireGuardBuildConfig) (*WireGuardConfig, error) {
	if g == nil {
		return nil, fmt.Errorf("nil compiled group")
	}
	out := &WireGuardConfig{}
	existing := make(map[Key]WireGuardPeer)
	if base != nil {
		out.Interface = cloneInterface(base.Interface)
		for _, p := range base.Peers {
			existing[p.PublicKey] = p
		}
	}

	desiredKeys := make(map[Key]struct{})
	for _, ap := range g.AllowedPeers {
		if cfg.LocalPeer != "" && ap.Peer.ID == cfg.LocalPeer {
			continue
		}
		if ap.Peer.PublicKey.IsZero() {
			return nil, &CompileError{
				Code:     ErrInvalidKey,
				Location: Location{Tenant: g.Tenant, Group: g.Group, Peer: ap.Peer.ID, Field: "public_key"},
				Message:  "allowed peer is missing a WireGuard public key",
			}
		}
		key := ap.Peer.PublicKey
		desiredKeys[key] = struct{}{}

		peer := WireGuardPeer{PublicKey: key, AllowedIPs: slices.Clone(ap.AllowedIPs)}
		if old, ok := existing[key]; ok {
			peer.PresharedKey = old.PresharedKey
			peer.Endpoint = old.Endpoint
			peer.PersistentKeepalive = old.PersistentKeepalive
			peer.Extra = slices.Clone(old.Extra)
			if cfg.MergeExistingAllowedIPs {
				peer.AllowedIPs = append(peer.AllowedIPs, old.AllowedIPs...)
			}
		} else if ap.Peer.Endpoint != "" {
			peer.Endpoint = ap.Peer.Endpoint
			peer.PersistentKeepalive = ap.Peer.PersistentKeepalive
		}
		peer.AllowedIPs = canonicalPrefixes(peer.AllowedIPs)
		out.Peers = append(out.Peers, peer)
	}

	if base != nil && cfg.PreserveUnmanagedPeers {
		for _, old := range base.Peers {
			if _, managed := desiredKeys[old.PublicKey]; managed {
				continue
			}
			clone := old
			clone.AllowedIPs = slices.Clone(old.AllowedIPs)
			clone.Extra = slices.Clone(old.Extra)
			out.Peers = append(out.Peers, clone)
		}
	}
	return out, nil
}

func cloneInterface(in WireGuardInterface) WireGuardInterface {
	in.Addresses = slices.Clone(in.Addresses)
	in.DNS = slices.Clone(in.DNS)
	in.Extra = slices.Clone(in.Extra)
	return in
}
