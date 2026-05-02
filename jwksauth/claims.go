package jwksauth

import (
	"fmt"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Claims holds the AuthGate-specific JWT claims plus a generic Extras map
// for any caller-supplied keys the issuer included in the payload.
//
// Domain, Project, and ServiceAccount are server-attested by AuthGate;
// configure the JWT payload prefix via [WithPrivateClaimPrefix]. Extras
// carries every other non-standard key — read individual values with
// [TokenInfo.Extra].
//
// Claims is populated by the SDK's verifier from a verified IDToken via
// custom decoding (not via struct-tag JSON unmarshal), so it deliberately
// carries no json tags — that keeps the struct from advertising payload
// keys that no longer match the prefixed wire format. As a side effect,
// passing a [Claims] value to encoding/json will marshal exported fields
// under their Go names ("ClientID", "Domain", ...) rather than the
// snake_case JWT keys; if you need the raw payload, read it from the
// embedded [oidc.IDToken] on [TokenInfo] instead.
type Claims struct {
	ClientID       string
	Scope          string
	Domain         string
	ServiceAccount string
	Project        string

	// Extras carries any payload keys that are neither JWT/OIDC standard
	// claims nor the three server-attested "<prefix>_..." keys. Values are
	// taken from the decoded JSON map by reference; callers should treat
	// them as read-only.
	Extras map[string]any
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

	// Claims is the decoded set of AuthGate custom claims plus Extras.
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

// Extra returns the value associated with key in [Claims.Extras] (comma-ok
// style). Returns (nil, false) when the key is absent or [Claims.Extras]
// is nil. Use this to read caller-supplied claims that the SDK does not
// expose as a named field.
func (t *TokenInfo) Extra(key string) (any, bool) {
	if t.Claims.Extras == nil {
		return nil, false
	}
	v, ok := t.Claims.Extras[key]
	return v, ok
}

// staticReservedClaimKeys is the set of payload keys this SDK
// intentionally excludes from Claims.Extras. It mirrors upstream
// AuthGate's reserved set, which mixes RFC 7519 standard JWT keys
// (iss, sub, aud, exp, nbf, iat, jti), a subset of OIDC keys (azp, amr,
// acr, auth_time, nonce, at_hash), and AuthGate-specific keys exposed
// as named [Claims] fields (scope, client_id) plus a few other
// AuthGate-emitted keys (type, user_id). It is NOT the full IANA OIDC
// claim registry — common OIDC claims the SDK does not name explicitly
// (e.g. email, name) will surface via Extras when the issuer emits them.
//
// The three server-attested keys are excluded dynamically by
// newTokenInfo via the resolved [claimKeys].
var staticReservedClaimKeys = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "exp": {}, "nbf": {}, "iat": {}, "jti": {},
	"type": {}, "scope": {}, "user_id": {}, "client_id": {},
	"azp": {}, "amr": {}, "acr": {}, "auth_time": {}, "nonce": {}, "at_hash": {},
}

// claimKeys holds the resolved "<prefix>_<logical>" payload keys for the
// three server-attested AuthGate claims. Construction-time once; read-only
// on the verify hot path.
type claimKeys struct {
	domain         string
	project        string
	serviceAccount string
}

// newClaimKeys composes the three server-attested payload keys from prefix.
// Mirrors upstream's EmittedName(prefix, logical) = prefix + "_" + logical.
func newClaimKeys(prefix string) claimKeys {
	return claimKeys{
		domain:         prefix + "_domain",
		project:        prefix + "_project",
		serviceAccount: prefix + "_service_account",
	}
}

// newTokenInfo decodes Claims and Extras from a verified IDToken using the
// resolved server-attested key names.
func newTokenInfo(tok *oidc.IDToken, keys claimKeys) (*TokenInfo, error) {
	var raw map[string]any
	if err := tok.Claims(&raw); err != nil {
		return nil, fmt.Errorf("decode JWT claims: %w", err)
	}

	c := Claims{
		ClientID:       stringFromRaw(raw, "client_id"),
		Scope:          stringFromRaw(raw, "scope"),
		Domain:         stringFromRaw(raw, keys.domain),
		Project:        stringFromRaw(raw, keys.project),
		ServiceAccount: stringFromRaw(raw, keys.serviceAccount),
	}

	for k, v := range raw {
		if _, reserved := staticReservedClaimKeys[k]; reserved {
			continue
		}
		if k == keys.domain || k == keys.project || k == keys.serviceAccount {
			continue
		}
		if c.Extras == nil {
			c.Extras = make(map[string]any)
		}
		c.Extras[k] = v
	}

	return &TokenInfo{
		IDToken: tok,
		Claims:  c,
		Scopes:  strings.Fields(c.Scope),
	}, nil
}

// stringFromRaw returns the string value of key in raw, or "" if absent or
// not a string. JWTs are string-only at the schema level for the keys we
// extract this way, so a non-string value is an anomalous token; the
// fail-closed AccessRule path handles missing values uniformly.
func stringFromRaw(raw map[string]any, key string) string {
	if v, ok := raw[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
