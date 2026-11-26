package grouppolicy

// TenantID identifies a tenant or NetBird account. It is a distinct type so
// tenant and group identifiers cannot be swapped at call sites.
type TenantID string

// GroupID identifies a group inside a tenant.
type GroupID string

// PolicyID identifies a policy inside a group.
type PolicyID string

// RuleID identifies a rule inside a policy.
type RuleID string

// PeerID identifies a peer inside a tenant.
type PeerID string

// RecordID identifies a DNS record.
type RecordID string
