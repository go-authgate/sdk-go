// Package jwksauth provides offline JWT/JWKS validation for resource servers.
//
// Use this package on the resource-server side of an AuthGate deployment to
// validate access tokens locally — no per-request callback to the issuer.
// Construction performs OIDC discovery; the JWKS itself is fetched lazily
// by go-oidc on the first verification (and again whenever a token header
// carries a previously-unknown key id), then cached in process so
// subsequent verifications are network-free.
//
// # When to choose offline vs. online validation
//
// This package complements the [github.com/go-authgate/sdk-go/middleware]
// package, which validates tokens by calling the issuer's tokeninfo or
// introspection endpoint per request. The trade-off is:
//
//   - Offline (this package): zero round-trips per request, microsecond
//     verification, scales horizontally, works in air-gapped regions after the
//     first JWKS fetch. A revoked token stays valid until its `exp`.
//   - Online (middleware): instant revocation visibility, but every request
//     pays a network round-trip to the issuer.
//
// Pick offline when access-token lifetimes are short (minutes) and you can
// tolerate the revocation window equalling the lifetime. Pick online when you
// need instant revocation.
//
// # Single issuer
//
// For a service that trusts one AuthGate:
//
//	v, err := jwksauth.NewVerifier(ctx, "https://auth.example.com", "https://api.example.com")
//	if err != nil { log.Fatal(err) }
//	mux.Handle("/api/profile", jwksauth.Middleware(v, jwksauth.AccessRule{})(profileHandler))
//	mux.Handle("/api/data",    jwksauth.Middleware(v, jwksauth.AccessRule{Scopes: []string{"email"}})(dataHandler))
//
// # Multiple issuers (multi-region / multi-domain / migration)
//
// AuthGate's hierarchy is two-level: a Domain (e.g. "oa", "swrd", "hwrd") is
// the top-level partition, and an optional Tenant (e.g. "a76", "a78") names
// a sub-room inside a Domain. Tokens carry domain and tenant as two
// independent claims; tokens for Domains that have no sub-room concept omit
// the tenant claim entirely.
//
// For a service that accepts tokens from several AuthGates:
//
//	mv, err := jwksauth.NewMultiVerifier(ctx,
//	    []string{"https://auth-a.example.com", "https://auth-b.example.com"},
//	    "https://api.example.com")
//	if err != nil { log.Fatal(err) }
//	// Optional cross-domain defense — strongly recommended with short
//	// domain codes. Tenants live entirely inside a Domain and are not part
//	// of cross-issuer pinning.
//	if err := mv.SetIssuerDomains("https://auth-a.example.com=oa,hwrd;https://auth-b.example.com=swrd"); err != nil {
//	    log.Fatal(err)
//	}
//	mux.Handle("/api/admin", jwksauth.Middleware(mv, jwksauth.AccessRule{
//	    Domains:         []string{"oa"},
//	    ServiceAccounts: []string{"sync-bot@oa.local"},
//	    Projects:        []string{"admin-tools"},
//	})(adminHandler))
//
// # Why "read iss before verifying" is safe (multi-issuer routing)
//
// When dispatching by issuer, the `iss` claim is read from the unverified
// JWT payload only to PICK the correct verifier. The chosen verifier then
// authoritatively validates the signature against ITS issuer's JWKS and
// re-checks the `iss` claim. An attacker who claims iss=trustedA but signs
// with their own key fails signature verification.
package jwksauth
