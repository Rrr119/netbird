package grouppolicy

import (
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

const defaultDNSTTL = 300

// RRType is a DNS record type.
type RRType string

const (
	// RRTypeA is an IPv4 address record.
	RRTypeA RRType = "A"
	// RRTypeAAAA is an IPv6 address record.
	RRTypeAAAA RRType = "AAAA"
)

// ErrNoSuchName is returned when a name is absent from a group's view. Names
// that exist but are not visible to the group produce the same error so DNS
// does not disclose the existence of other groups' records.
var ErrNoSuchName = errors.New("grouppolicy: name not visible in group DNS view")

// DNSRecord is one answer in a compiled DNSView.
type DNSRecord struct {
	// Name is the normalized record name.
	Name string
	// Type is A or AAAA.
	Type RRType
	// Addr is the answer address.
	Addr netip.Addr
	// TTL is the record time to live in seconds.
	TTL uint32
}

// DNSView is the DNS configuration one group is allowed to see. It is safe
// for concurrent lookups after compilation.
type DNSView struct {
	tenant        TenantID
	group         GroupID
	upstreams     []string
	searchDomains []string
	names         []string
	byName        map[string][]DNSRecord
}

// Tenant returns the tenant this view belongs to.
func (v *DNSView) Tenant() TenantID { return v.tenant }

// Group returns the group this view belongs to.
func (v *DNSView) Group() GroupID { return v.group }

// Upstreams returns the group-specific upstream resolvers.
func (v *DNSView) Upstreams() []string { return slices.Clone(v.upstreams) }

// SearchDomains returns the group-specific search domains.
func (v *DNSView) SearchDomains() []string { return slices.Clone(v.searchDomains) }

// Names returns the sorted DNS names visible to the group.
func (v *DNSView) Names() []string { return slices.Clone(v.names) }

// Records returns all records in the view sorted by name and address.
func (v *DNSView) Records() []DNSRecord {
	var out []DNSRecord
	for _, name := range v.names {
		out = append(out, v.byName[name]...)
	}
	return out
}

// Resolve returns the answers for name and qtype. An empty qtype or "ANY"
// returns every address type. Names hidden from the group are reported as
// ErrNoSuchName.
func (v *DNSView) Resolve(name string, qtype RRType) ([]netip.Addr, error) {
	if v == nil {
		return nil, ErrNoSuchName
	}
	records, ok := v.byName[normalizeName(name)]
	if !ok || len(records) == 0 {
		return nil, ErrNoSuchName
	}

	want := RRType(strings.ToUpper(string(qtype)))
	var addrs []netip.Addr
	for _, r := range records {
		if want != "" && want != "ANY" && r.Type != want {
			continue
		}
		addrs = append(addrs, r.Addr)
	}
	if len(addrs) == 0 {
		return nil, ErrNoSuchName
	}
	return addrs, nil
}

func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

func recordType(addr netip.Addr) RRType {
	if addr.Is4() {
		return RRTypeA
	}
	return RRTypeAAAA
}

// buildDNSView compiles the DNS view for viewer. Invalid records owned by the
// viewer are returned as located errors; invalid records owned by other
// groups are skipped here and reported when their own group compiles, so one
// bad record cannot break another group's view.
func buildDNSView(tc *tenantCtx, viewer GroupID) (*DNSView, CompileErrors) {
	viewerGroup := tc.groups[viewer]
	view := &DNSView{
		tenant:        tc.id,
		group:         viewer,
		byName:        make(map[string][]DNSRecord),
		upstreams:     slices.Clone(viewerGroup.DNS.Upstreams),
		searchDomains: slices.Clone(viewerGroup.DNS.SearchDomains),
	}

	var errs CompileErrors
	for _, ownerID := range tc.groupOrder {
		owner := tc.groups[ownerID]
		for i, spec := range owner.DNS.Records {
			field := "dns.records[" + strconv.Itoa(i) + "]"
			valid := strings.TrimSpace(spec.Name) != ""
			addrs := selectDNSAnswers(spec, viewer)
			for _, a := range addrs {
				if !a.IsValid() {
					valid = false
				}
			}
			if !valid {
				if ownerID == viewer {
					errs = append(errs, &CompileError{
						Code:     ErrInvalidDNSRecord,
						Location: Location{Tenant: tc.id, Group: ownerID, Field: field + ".name", Pos: spec.Pos},
						Message:  "DNS record needs a name and valid addresses",
					})
				}
				continue
			}
			if !dnsVisible(spec, ownerID, viewer) {
				continue
			}

			name := normalizeName(spec.Name)
			ttl := spec.TTL
			if ttl == 0 {
				ttl = defaultDNSTTL
			}
			for _, addr := range addrs {
				addr = addr.Unmap()
				view.byName[name] = append(view.byName[name], DNSRecord{
					Name: name, Type: recordType(addr), Addr: addr, TTL: ttl,
				})
			}
		}
	}

	for name, records := range view.byName {
		slices.SortFunc(records, func(a, b DNSRecord) int {
			if a.Type != b.Type {
				return strings.Compare(string(a.Type), string(b.Type))
			}
			return strings.Compare(a.Addr.String(), b.Addr.String())
		})
		view.byName[name] = slices.CompactFunc(records, func(a, b DNSRecord) bool {
			return a.Type == b.Type && a.Addr == b.Addr
		})
		view.names = append(view.names, name)
	}
	slices.Sort(view.names)

	if len(errs) > 0 {
		return nil, errs
	}
	return view, nil
}

func selectDNSAnswers(spec DNSRecordSpec, viewer GroupID) []netip.Addr {
	if override, ok := spec.Answers[viewer]; ok && len(override) > 0 {
		return override
	}
	return spec.Addrs
}

func dnsVisible(spec DNSRecordSpec, owner, viewer GroupID) bool {
	if owner == viewer || spec.Shared {
		return true
	}
	return slices.Contains(spec.VisibleGroups, viewer)
}
