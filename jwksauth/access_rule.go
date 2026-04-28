package jwksauth

import (
	"fmt"
	"slices"
	"strings"
)

// AccessRule is a per-route policy: the OAuth scopes the caller must hold
// plus optional allowlists for the tenant / service_account / project
// claims AuthGate may emit.
//
// Semantics:
//   - An empty slice means "this dimension is not checked".
//   - A populated slice is fail-closed: the token's value must appear in
//     the slice (a missing claim is treated as not-in-allowlist).
//   - Tenants is matched case-insensitively. Callers may supply values in
//     any case; [Middleware] canonicalizes the rule on construction by
//     lower-casing tenant allowlist entries.
//   - ServiceAccounts and Projects are matched exactly (case-sensitive).
//
// Construct rules per-route, not globally — different endpoints typically
// have different allowlists.
type AccessRule struct {
	// Scopes are the OAuth scopes that must be present. Missing scopes are
	// reported via RFC 6750 §3.1 insufficient_scope (HTTP 403) so the
	// client knows what to request next time.
	Scopes []string

	// Tenants is the allowlist of tenant codes (case-insensitive).
	Tenants []string

	// ServiceAccounts is the allowlist of service-account identifiers
	// (case-sensitive, exact match).
	ServiceAccounts []string

	// Projects is the allowlist of project identifiers (case-sensitive,
	// exact match).
	Projects []string
}

// canonical returns a copy of the rule with allowlist values normalized
// and slices cloned so callers can safely mutate theirs after registration.
//
// Every entry is trimmed and empty results are dropped — otherwise a stray
// "" (e.g. from a trailing comma in operator config) would let a token
// whose claim is missing/empty pass the allowlist, silently breaking the
// documented fail-closed semantics for missing claims.
//
// Tenants are additionally lower-cased so [AccessRule.Tenants] comparisons
// are case-insensitive at the rule side.
func (r AccessRule) canonical() AccessRule {
	out := AccessRule{
		Scopes:          trimNonEmpty(r.Scopes, false),
		Tenants:         trimNonEmpty(r.Tenants, true),
		ServiceAccounts: trimNonEmpty(r.ServiceAccounts, false),
		Projects:        trimNonEmpty(r.Projects, false),
	}
	return out
}

func trimNonEmpty(in []string, lower bool) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if lower {
			s = strings.ToLower(s)
		}
		out = append(out, s)
	}
	return out
}

// checkClaims validates the non-scope dimensions and returns a server-log
// reason on failure. Scope checks live in [Middleware] proper because
// they need to advertise the missing scope on the WWW-Authenticate header.
func (r AccessRule) checkClaims(info *TokenInfo) (reason string, ok bool) {
	if len(r.Tenants) > 0 && !slices.Contains(r.Tenants, info.Tenant()) {
		return fmt.Sprintf("tenant=%q not in allowlist", info.Claims.Tenant), false
	}
	if len(r.ServiceAccounts) > 0 &&
		!slices.Contains(r.ServiceAccounts, info.Claims.ServiceAccount) {
		return fmt.Sprintf("service_account=%q not in allowlist", info.Claims.ServiceAccount), false
	}
	if len(r.Projects) > 0 && !slices.Contains(r.Projects, info.Claims.Project) {
		return fmt.Sprintf("project=%q not in allowlist", info.Claims.Project), false
	}
	return "", true
}
