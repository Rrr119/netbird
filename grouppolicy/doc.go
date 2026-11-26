// Package grouppolicy compiles one shared multi-tenant policy document into
// independent per-group artifacts.
//
// In a NetBird deployment the management service stores every account's
// groups, policies and DNS settings together. A change to one group's
// policy must not alter the rules, DNS view or WireGuard configuration that
// every other group receives. This package makes that boundary explicit:
//
//   - CompileAll expands the shared Config into an immutable Bundle of
//     CompiledGroup values, one per tenant/group. Each group is compiled in
//     isolation, so an invalid policy reports a Location that names the
//     tenant, group, policy, rule and field without discarding the healthy
//     groups.
//   - Bundle.NewEnforcer evaluates flows with default-deny semantics. It is
//     the in-process reference for the ACL rules the client programs into
//     its firewall backends.
//   - CompiledGroup.DNS is a DNSView that contains only the records visible
//     to that group and supports split-horizon answers. Hidden names are
//     answered as no-such-name so DNS does not become an existence oracle.
//   - CompiledGroup.BuildWireGuardConfig projects the accepted destinations
//     into WireGuard AllowedIPs and reads and writes the canonical INI
//     configuration used by WireGuard and wg-quick, preserving interface
//     and peer fields from an existing configuration.
//
// The package has no third-party dependencies so that it can be shared by
// the management compiler and the client without pulling in firewall, DNS
// server or WireGuard device packages.
package grouppolicy
