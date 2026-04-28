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
// If a deployment uses namespaced claims (e.g.
// "https://authgate.example.com/tenant"), copy this struct and adjust the
// json tags rather than monkey-patching the SDK.
type Claims struct {
	ClientID       string `json:"client_id,omitempty"`
	Scope          string `json:"scope,omitempty"`
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

	// tenant is the case-folded form of Claims.Tenant, used internally for
	// allowlist comparison. Exposed read-only via Tenant().
	tenant string
}

// HasScope reports whether the token carries the named OAuth scope.
func (t *TokenInfo) HasScope(scope string) bool {
	return slices.Contains(t.Scopes, scope)
}

// Tenant returns the case-folded tenant code used for [AccessRule] allowlist
// comparisons. Use t.Claims.Tenant if you need the original case.
func (t *TokenInfo) Tenant() string {
	return t.tenant
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
		tenant:  strings.ToLower(extra.Tenant),
	}, nil
}
