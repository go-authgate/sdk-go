package jwksauth

import (
	"fmt"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Claims holds the non-standard JWT claims AuthGate emits in the payload.
// All fields are optional — services that don't use a given dimension can
// leave the corresponding [AccessRule] slice empty and the claim is ignored.
//
// AuthGate's hierarchy is two-level: a Domain (e.g. "oa", "swrd", "hwrd") is
// the top-level partition, and an optional Tenant (e.g. "a76", "a78") names
// a sub-room inside a Domain. Tokens for Domains that have no sub-room
// concept simply omit the tenant claim.
//
// If a deployment uses namespaced claims (e.g.
// "https://authgate.example.com/domain"), copy this struct and adjust the
// json tags rather than monkey-patching the SDK.
type Claims struct {
	ClientID       string `json:"client_id,omitempty"`
	Scope          string `json:"scope,omitempty"`
	Domain         string `json:"domain,omitempty"`
	Tenant         string `json:"tenant,omitempty"`
	ServiceAccount string `json:"service_account,omitempty"`
	Project        string `json:"project,omitempty"`
}

// TokenInfo is the result of a successful verification. It embeds the
// verified [oidc.IDToken] (so callers can read iss, sub, aud, exp, nbf
// directly) and adds the parsed AuthGate-specific Claims plus the scope
// list pre-split for fast HasScope checks.
//
// The verifier already validated signature, iss, aud, exp and nbf; consumers
// can rely on every field of the embedded IDToken without re-checking.
type TokenInfo struct {
	*oidc.IDToken

	// Claims is the decoded set of AuthGate custom claims.
	Claims Claims

	// Scopes is the parsed scope list (strings.Fields(Claims.Scope)) cached
	// for fast HasScope() lookups.
	Scopes []string
}

// HasScope reports whether the token carries the named OAuth scope.
func (t *TokenInfo) HasScope(scope string) bool {
	return slices.Contains(t.Scopes, scope)
}

// Domain returns the case-folded domain code used for [AccessRule] allowlist
// comparisons. Use t.Claims.Domain if you need the original case.
func (t *TokenInfo) Domain() string {
	return strings.ToLower(t.Claims.Domain)
}

// Tenant returns the case-folded tenant code (the optional sub-room inside a
// Domain). Returns "" when the token has no tenant claim — that is the
// documented "Domain has no sub-room" signal. Use t.Claims.Tenant if you
// need the original case.
func (t *TokenInfo) Tenant() string {
	return strings.ToLower(t.Claims.Tenant)
}

// newTokenInfo decodes the AuthGate-specific Claims from a verified IDToken
// and assembles the TokenInfo struct returned by both verifiers.
func newTokenInfo(tok *oidc.IDToken) (*TokenInfo, error) {
	var extra Claims
	if err := tok.Claims(&extra); err != nil {
		return nil, fmt.Errorf("decode JWT claims: %w", err)
	}
	return &TokenInfo{
		IDToken: tok,
		Claims:  extra,
		Scopes:  strings.Fields(extra.Scope),
	}, nil
}
