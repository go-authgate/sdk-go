# jwksauth

Offline JWT/JWKS validation for AuthGate resource servers. Validate tokens
locally against cached signing keys — no per-request callback to the issuer.

## Online vs. offline validation

This package complements [`middleware/`](../middleware/), which calls the
issuer's tokeninfo or introspection endpoint per request. Pick the model
that matches your latency/revocation trade-off:

| Concern                          | `jwksauth` (offline)             | `middleware` (online)              |
| -------------------------------- | -------------------------------- | ---------------------------------- |
| Per-request network round-trips  | None (signature math only)       | One per request                    |
| Verification latency             | Microseconds                     | 10–50 ms + auth-server tail        |
| Revocation visibility            | After `exp` of the access token  | Instant                            |
| Survives auth-server outage      | Yes (after first JWKS fetch)     | No                                 |
| Works with opaque (non-JWT) toks | No — JWT only                    | Yes                                |
| Edge / air-gapped deployments    | Suitable                         | Requires reachable auth server     |

Common pattern: short access-token lifetimes (5–15 min) + offline JWKS for
the hot path, online introspection for revocation-sensitive mutations.

## Single issuer

```go
import "github.com/go-authgate/sdk-go/jwksauth"

ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
defer cancel()
v, err := jwksauth.NewVerifier(ctx, "https://auth.example.com", "https://api.example.com")
if err != nil { log.Fatal(err) }

mux := http.NewServeMux()
mux.Handle("/api/profile",
    jwksauth.Middleware(v, jwksauth.AccessRule{})(http.HandlerFunc(profile)))
mux.Handle("/api/data",
    jwksauth.Middleware(v, jwksauth.AccessRule{Scopes: []string{"email"}})(http.HandlerFunc(data)))
```

If your issuer doesn't emit `aud` on access tokens, use `NewVerifierSkipAudience`
to opt out explicitly. The audience-required-by-default API prevents silent
misconfiguration.

In your handler:

```go
func profile(w http.ResponseWriter, r *http.Request) {
    info, ok := jwksauth.TokenInfoFromContext(r.Context())
    if !ok {
        http.Error(w, "internal server error", http.StatusInternalServerError)
        return
    }
    // info embeds *oidc.IDToken — use info.Subject, info.Audience, info.Expiry, etc.
    // info.Claims carries the AuthGate custom claims.
    json.NewEncoder(w).Encode(map[string]any{
        "subject": info.Subject,
        "scope":   info.Claims.Scope,
    })
}
```

## Multiple issuers

For multi-region / multi-tenant / migration deployments, build a
`MultiVerifier`. It runs OIDC discovery for every issuer in parallel
(bounded by a single total timeout) and routes each request to the right
verifier based on the token's `iss` claim.

```go
mv, err := jwksauth.NewMultiVerifier(ctx,
    []string{"https://auth-a.example.com", "https://auth-b.example.com"},
    "https://api.example.com")
if err != nil { log.Fatal(err) }

// Optional: pin each issuer to the tenant codes it owns. With short
// tenant codes ("oa" / "hwrd" / "swrd") this stops a compromised issuer
// from minting tokens that claim a tenant owned by another issuer.
if err := mv.SetIssuerTenants(
    "https://auth-a.example.com=oa,hwrd;https://auth-b.example.com=swrd",
); err != nil {
    log.Fatal(err)
}

mux.Handle("/api/admin", jwksauth.Middleware(mv, jwksauth.AccessRule{
    ServiceAccounts: []string{"sync-bot@oa.local"},
    Projects:        []string{"admin-tools"},
})(http.HandlerFunc(admin)))
```

`SetIssuerTenants` validates strictly:

- Every issuer registered with the verifier must appear in the string.
- A tenant must be owned by exactly one issuer.
- Same-issuer duplicates (`oa,oa`) are reported as typos so the error points
  at the actual mistake rather than a confusing cross-issuer overlap message.

## AccessRule

Per-route policy; an empty slice means "this dimension is not checked".

| Field             | Required claim     | Match     | Notes                                 |
| ----------------- | ------------------ | --------- | ------------------------------------- |
| `Scopes`          | `scope`            | space-set | Reports `403 insufficient_scope` and advertises the scope on `WWW-Authenticate` |
| `Tenants`         | `tenant`           | case-fold | SDK lower-cases the rule on registration |
| `ServiceAccounts` | `service_account`  | exact     | Case-sensitive                        |
| `Projects`        | `project`          | exact     | Case-sensitive                        |

Allowlist mismatches return `401 invalid_token` (generic) so the allowlist
itself is not probeable. The full reason is logged server-side via the
configured logger (defaults to `log.Default()`; override with
`jwksauth.WithLogger`).

## RFC 6750 error responses

The middleware emits standards-compliant `WWW-Authenticate` challenges:

| Situation                     | Status | `WWW-Authenticate`                                                            |
| ----------------------------- | ------ | ----------------------------------------------------------------------------- |
| Missing Authorization header  | 401    | `Bearer`                                                                      |
| Token verification fails      | 401    | `Bearer error="invalid_token", error_description="invalid token"`             |
| Required scope missing        | 403    | `Bearer error="insufficient_scope", error_description="...", scope="<scope>"` |

`ExtractBearerToken` and `WriteAuthError` are exported so applications can
reuse them in custom handlers without duplicating the parser/writer.

## Server hardening

When using `MultiVerifier`, bound the Authorization header well below the
Go default (1 MiB) so the unverified-payload base64 decode (used to read
`iss` for routing) cannot be coerced into large allocations:

```go
srv := &http.Server{
    Handler:        mux,
    MaxHeaderBytes: 8 << 10, // real access tokens are typically <2 KiB
}
```

## Why "read iss before verifying" is safe (multi-issuer)

`UnverifiedIssuer` reads `iss` from the JWT payload **without** validating
the signature. The result is used only to pick which verifier to dispatch
to; the chosen verifier then authoritatively re-checks signature, `iss`,
`aud`, `exp`, and `nbf`. An attacker who claims `iss=trustedA` but signs
with their own key fails signature verification.
