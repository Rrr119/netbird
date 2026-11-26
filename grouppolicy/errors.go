package grouppolicy

import (
	"errors"
	"fmt"
	"strings"
)

// ErrCode identifies a class of policy compilation failure.
type ErrCode string

const (
	// ErrInvalidConfig marks a document-level inconsistency.
	ErrInvalidConfig ErrCode = "invalid_config"
	// ErrUnknownGroup marks a selector that names a missing group.
	ErrUnknownGroup ErrCode = "unknown_group"
	// ErrUnknownPeer marks a selector that names a missing peer.
	ErrUnknownPeer ErrCode = "unknown_peer"
	// ErrDuplicateID marks a repeated tenant, group, policy or rule id.
	ErrDuplicateID ErrCode = "duplicate_id"
	// ErrInvalidSelector marks a malformed source or destination selector.
	ErrInvalidSelector ErrCode = "invalid_selector"
	// ErrInvalidCIDR marks a CIDR or IP selector that cannot be parsed.
	ErrInvalidCIDR ErrCode = "invalid_cidr"
	// ErrInvalidPort marks a port specification that cannot be parsed.
	ErrInvalidPort ErrCode = "invalid_port"
	// ErrInvalidProtocol marks an unsupported protocol.
	ErrInvalidProtocol ErrCode = "invalid_protocol"
	// ErrInvalidAction marks an unsupported action.
	ErrInvalidAction ErrCode = "invalid_action"
	// ErrEmptySelector marks a rule with no sources or no destinations.
	ErrEmptySelector ErrCode = "empty_selector"
	// ErrInvalidKey marks a malformed WireGuard key.
	ErrInvalidKey ErrCode = "invalid_key"
	// ErrInvalidDNSRecord marks a DNS record that cannot be compiled.
	ErrInvalidDNSRecord ErrCode = "invalid_dns_record"
)

// Location pinpoints the configuration element that failed to compile. Every
// field is optional except the context the compiler knew about.
type Location struct {
	// Tenant is the tenant/account being compiled.
	Tenant TenantID
	// Group is the group whose artifact was being built.
	Group GroupID
	// Policy is the policy containing the failure.
	Policy PolicyID
	// Rule is the rule identifier when one was provided.
	Rule RuleID
	// RuleIndex is the 0-based rule index within the policy, or -1.
	RuleIndex int
	// Field is the concrete field, for example destinations[0].
	Field string
	// Peer is the peer when the failure is peer-specific.
	Peer PeerID
	// Pos is the source document position when the caller supplied one.
	Pos SourcePosition
}

// CompileError is one located policy compilation failure.
type CompileError struct {
	// Code is the machine-readable failure class.
	Code ErrCode
	// Location locates the failing element.
	Location Location
	// Message is the human readable reason.
	Message string
	// Err wraps the underlying parsing error, if any.
	Err error
}

func (e *CompileError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "grouppolicy[%s]: %s", e.Code, e.Message)

	var loc []string
	if e.Location.Tenant != "" {
		loc = append(loc, "tenant="+string(e.Location.Tenant))
	}
	if e.Location.Group != "" {
		loc = append(loc, "group="+string(e.Location.Group))
	}
	if e.Location.Policy != "" {
		loc = append(loc, "policy="+string(e.Location.Policy))
	}
	if e.Location.Rule != "" {
		loc = append(loc, "rule="+string(e.Location.Rule))
	}
	if e.Location.RuleIndex >= 0 {
		loc = append(loc, fmt.Sprintf("rule_index=%d", e.Location.RuleIndex))
	}
	if e.Location.Peer != "" {
		loc = append(loc, "peer="+string(e.Location.Peer))
	}
	if e.Location.Field != "" {
		loc = append(loc, "field="+e.Location.Field)
	}
	if pos := e.Location.Pos.String(); pos != "" {
		loc = append(loc, "at="+pos)
	}
	if len(loc) > 0 {
		b.WriteString(" (")
		b.WriteString(strings.Join(loc, " "))
		b.WriteString(")")
	}
	return b.String()
}

// Unwrap returns the underlying error.
func (e *CompileError) Unwrap() error { return e.Err }

// CompileErrors aggregates every failure found while compiling a document or
// group. It keeps successful per-group artifacts usable.
type CompileErrors []*CompileError

func (es CompileErrors) Error() string {
	parts := make([]string, 0, len(es))
	for _, e := range es {
		if e != nil {
			parts = append(parts, e.Error())
		}
	}
	return strings.Join(parts, "\n")
}

// Unwrap enables errors.Is and errors.As across the aggregated failures.
func (es CompileErrors) Unwrap() []error {
	out := make([]error, 0, len(es))
	for _, e := range es {
		if e != nil {
			out = append(out, e)
		}
	}
	return out
}

// OrNil returns the aggregate as an error, or nil when empty.
func (es CompileErrors) OrNil() error {
	if len(es) == 0 {
		return nil
	}
	return es
}

// AsCompileErrors reports whether err contains a CompileErrors aggregate and
// returns it. It is a small wrapper around errors.As for callers that want
// the structured locations.
func AsCompileErrors(err error) (CompileErrors, bool) {
	var es CompileErrors
	if errors.As(err, &es) {
		return es, true
	}
	var one *CompileError
	if errors.As(err, &one) {
		return CompileErrors{one}, true
	}
	return nil, false
}
