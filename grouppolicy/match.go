package grouppolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// PortRange is an inclusive destination port interval.
type PortRange struct {
	// From is the first port in the range.
	From uint16
	// To is the last port in the range.
	To uint16
}

// ParsePortSpec parses "80", "443" or "8000-8080" into a PortRange.
func ParsePortSpec(spec string) (PortRange, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return PortRange{}, errors.New("empty port")
	}
	if left, right, ok := strings.Cut(s, "-"); ok {
		from, err := parsePortNumber(strings.TrimSpace(left))
		if err != nil {
			return PortRange{}, err
		}
		to, err := parsePortNumber(strings.TrimSpace(right))
		if err != nil {
			return PortRange{}, err
		}
		if from > to {
			return PortRange{}, fmt.Errorf("port range %d-%d is reversed", from, to)
		}
		return PortRange{From: from, To: to}, nil
	}
	port, err := parsePortNumber(s)
	if err != nil {
		return PortRange{}, err
	}
	return PortRange{From: port, To: port}, nil
}

func parsePortNumber(s string) (uint16, error) {
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil || v == 0 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return uint16(v), nil
}

func portInRanges(port uint16, ranges []PortRange) bool {
	if len(ranges) == 0 {
		return true
	}
	for _, r := range ranges {
		if port >= r.From && port <= r.To {
			return true
		}
	}
	return false
}

type selectorKind int

const (
	selectorAny selectorKind = iota
	selectorGroup
	selectorPeer
	selectorPrefix
)

type selector struct {
	kind   selectorKind
	group  GroupID
	peer   PeerID
	prefix netip.Prefix
}

func parseSelectorRef(ref string) (selector, error) {
	s := strings.TrimSpace(ref)
	if s == "" {
		return selector{}, errors.New("empty selector")
	}
	if s == "*" || strings.EqualFold(s, "any") {
		return selector{kind: selectorAny}, nil
	}
	if raw, ok := strings.CutPrefix(s, "group:"); ok {
		id := strings.TrimSpace(raw)
		if id == "" {
			return selector{}, fmt.Errorf("invalid group selector %q", ref)
		}
		return selector{kind: selectorGroup, group: GroupID(id)}, nil
	}
	if raw, ok := strings.CutPrefix(s, "peer:"); ok {
		id := strings.TrimSpace(raw)
		if id == "" {
			return selector{}, fmt.Errorf("invalid peer selector %q", ref)
		}
		return selector{kind: selectorPeer, peer: PeerID(id)}, nil
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return selector{}, fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked()
		return selector{kind: selectorPrefix, prefix: p}, nil
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return selector{kind: selectorPrefix, prefix: addrPrefix(addr)}, nil
	}
	return selector{kind: selectorGroup, group: GroupID(s)}, nil
}

func addrPrefix(addr netip.Addr) netip.Prefix {
	addr = addr.Unmap()
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(addr, bits)
}

// MatchSet is the expanded, enforceable form of a list of selectors.
type MatchSet struct {
	// Any matches every principal or address.
	Any bool
	// PeerIDs are the concrete peers reached by group or peer selectors.
	PeerIDs []PeerID
	// Prefixes contains CIDR selectors and the /32 or /128 addresses of
	// every expanded peer.
	Prefixes []netip.Prefix
}

func (m MatchSet) matchesPeer(peer Peer, addr netip.Addr) bool {
	if m.Any {
		return true
	}
	for _, id := range m.PeerIDs {
		if id == peer.ID {
			return true
		}
	}
	if addr.IsValid() && m.containsAddr(addr) {
		return true
	}
	return false
}

func (m MatchSet) matchesDestination(addr netip.Addr) bool {
	if m.Any {
		return true
	}
	if !addr.IsValid() {
		return false
	}
	return m.containsAddr(addr)
}

func (m MatchSet) containsAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range m.Prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

type matchSetBuilder struct {
	set     MatchSet
	peerIDs map[PeerID]struct{}
	prefix  map[string]netip.Prefix
}

func newMatchSetBuilder() *matchSetBuilder {
	return &matchSetBuilder{
		peerIDs: make(map[PeerID]struct{}),
		prefix:  make(map[string]netip.Prefix),
	}
}

func (b *matchSetBuilder) any() { b.set.Any = true }

func (b *matchSetBuilder) addPeer(p Peer) {
	b.peerIDs[p.ID] = struct{}{}
	for _, a := range p.Addrs {
		pfx := addrPrefix(a)
		b.prefix[pfx.String()] = pfx
	}
}

func (b *matchSetBuilder) addPrefix(p netip.Prefix) {
	p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked()
	b.prefix[p.String()] = p
}

func (b *matchSetBuilder) build() MatchSet {
	if b.set.Any {
		return MatchSet{Any: true}
	}
	out := MatchSet{}
	for id := range b.peerIDs {
		out.PeerIDs = append(out.PeerIDs, id)
	}
	sort.Slice(out.PeerIDs, func(i, j int) bool { return out.PeerIDs[i] < out.PeerIDs[j] })
	for _, p := range b.prefix {
		out.Prefixes = append(out.Prefixes, p)
	}
	sort.Slice(out.Prefixes, func(i, j int) bool { return out.Prefixes[i].String() < out.Prefixes[j].String() })
	return out
}
