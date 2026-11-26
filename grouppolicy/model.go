package grouppolicy

import (
	"net/netip"
	"strconv"
)

// Action is the verdict a rule applies when it matches.
type Action string

const (
	// ActionAccept allows the matched flow, matching NetBird's accept action.
	ActionAccept Action = "accept"
	// ActionDrop denies the matched flow, matching NetBird's drop action.
	ActionDrop Action = "drop"
)

// Protocol is the transport protocol a rule matches.
type Protocol string

const (
	// ProtocolAll matches every protocol.
	ProtocolAll Protocol = "all"
	// ProtocolTCP matches TCP.
	ProtocolTCP Protocol = "tcp"
	// ProtocolUDP matches UDP.
	ProtocolUDP Protocol = "udp"
	// ProtocolICMP matches ICMP and ICMPv6.
	ProtocolICMP Protocol = "icmp"
)

// SourcePosition points at a location in the source document a policy was
// loaded from. The zero value means the caller did not provide positions.
type SourcePosition struct {
	// File is the configuration file or document name.
	File string `json:"file,omitempty"`
	// Line is the 1-based line number.
	Line int `json:"line,omitempty"`
	// Column is the optional 1-based column number.
	Column int `json:"column,omitempty"`
}

// String renders the position as file:line or file:line:column.
func (p SourcePosition) String() string {
	if p == (SourcePosition{}) {
		return ""
	}
	if p.File == "" && p.Line == 0 {
		return ""
	}
	out := p.File
	if p.Line > 0 {
		if out != "" {
			out += ":"
		}
		out += strconv.Itoa(p.Line)
		if p.Column > 0 {
			out += ":" + strconv.Itoa(p.Column)
		}
	}
	return out
}

// Config is the shared multi-tenant policy document. Every tenant, group,
// policy and DNS zone lives in this one structure; the compiler splits it
// into isolated per-group artifacts.
type Config struct {
	// Tenants holds all tenants (accounts) in the document.
	Tenants []Tenant `json:"tenants"`
}

// Tenant is an isolated account boundary. Groups and peers never leak across
// tenants.
type Tenant struct {
	// ID is the tenant/account identifier.
	ID TenantID `json:"id"`
	// Groups are the policy groups in this tenant.
	Groups []Group `json:"groups"`
	// Peers is the tenant-wide peer directory. Peer.Group membership drives
	// selector expansion.
	Peers []Peer `json:"peers"`
}

// Group owns a set of policies and a DNS view.
type Group struct {
	// ID is the group identifier, unique within the tenant.
	ID GroupID `json:"id"`
	// Policies are the policies attached to this group.
	Policies []Policy `json:"policies,omitempty"`
	// DNS is the group-specific DNS configuration and records.
	DNS DNSConfig `json:"dns,omitempty"`
}

// Peer is one enrolled machine or workload. A peer may belong to several
// groups.
type Peer struct {
	// ID is the stable peer identifier.
	ID PeerID `json:"id"`
	// Groups are the groups this peer belongs to.
	Groups []GroupID `json:"groups,omitempty"`
	// Addrs are the overlay addresses assigned to the peer.
	Addrs []netip.Addr `json:"addrs,omitempty"`
	// PublicKey is the peer's WireGuard public key. It may be zero when the
	// peer has not been configured for WireGuard yet.
	PublicKey Key `json:"public_key,omitempty"`
	// Endpoint is the optional host:port WireGuard endpoint.
	Endpoint string `json:"endpoint,omitempty"`
	// PersistentKeepalive is the WireGuard keepalive interval in seconds.
	PersistentKeepalive uint16 `json:"persistent_keepalive,omitempty"`
}

// Policy is a named collection of rules owned by one group.
type Policy struct {
	// ID is the policy identifier, unique within the group.
	ID PolicyID `json:"id"`
	// Name is the human readable policy name.
	Name string `json:"name,omitempty"`
	// Disabled excludes the policy from compilation. The zero value means
	// enabled, so a freshly authored policy is active.
	Disabled bool `json:"disabled,omitempty"`
	// Rules are the ordered rules of the policy.
	Rules []Rule `json:"rules,omitempty"`
	// Pos is the optional source location of the policy declaration.
	Pos SourcePosition `json:"pos,omitempty"`
}

// Rule is one match/action entry. Source and destination selectors accept
// group IDs, the "peer:<id>" form, IP addresses and CIDRs, and "*" for any.
type Rule struct {
	// ID is the rule identifier, unique within the policy.
	ID RuleID `json:"id,omitempty"`
	// Name is an optional readable name.
	Name string `json:"name,omitempty"`
	// Disabled excludes the rule from compilation.
	Disabled bool `json:"disabled,omitempty"`
	// Action is accept or drop. The empty value compiles as accept.
	Action Action `json:"action,omitempty"`
	// Protocol is all, tcp, udp or icmp. The empty value compiles as all.
	Protocol Protocol `json:"protocol,omitempty"`
	// Sources are source selectors.
	Sources []string `json:"sources,omitempty"`
	// Destinations are destination selectors.
	Destinations []string `json:"destinations,omitempty"`
	// Ports are port specs such as "443" or "8000-8080". Empty matches any.
	Ports []string `json:"ports,omitempty"`
	// Bidirectional also matches the reply direction.
	Bidirectional bool `json:"bidirectional,omitempty"`
	// Pos is the optional source location of the rule declaration.
	Pos SourcePosition `json:"pos,omitempty"`
}

// DNSConfig is the DNS data compiled into a group's isolated view.
type DNSConfig struct {
	// Upstreams are the group-specific upstream resolvers.
	Upstreams []string `json:"upstreams,omitempty"`
	// SearchDomains are the group-specific search domains.
	SearchDomains []string `json:"search_domains,omitempty"`
	// Records are DNS records owned by this group.
	Records []DNSRecordSpec `json:"records,omitempty"`
}

// DNSRecordSpec is one DNS record. Address family selects A versus AAAA.
type DNSRecordSpec struct {
	// ID is the optional record identifier used in error locations.
	ID RecordID `json:"id,omitempty"`
	// Name is the fully or partially qualified record name.
	Name string `json:"name"`
	// Addrs are the default answers.
	Addrs []netip.Addr `json:"addrs,omitempty"`
	// VisibleGroups grants resolution to additional groups. The owner group
	// always sees the record.
	VisibleGroups []GroupID `json:"visible_groups,omitempty"`
	// Shared makes the record visible to every group in the tenant.
	Shared bool `json:"shared,omitempty"`
	// Answers provides split-horizon answers keyed by viewing group.
	Answers map[GroupID][]netip.Addr `json:"answers,omitempty"`
	// TTL is the record time to live in seconds. Zero defaults to 300.
	TTL uint32 `json:"ttl,omitempty"`
	// Pos is the optional source location of the record.
	Pos SourcePosition `json:"pos,omitempty"`
}
