// Package jwksauth provides offline JWT/JWKS validation for resource servers.
//
// Use this package on the resource-server side of an AuthGate deployment to
// validate access tokens locally — no per-request callback to the issuer.
// The signing keys are fetched from the issuer's JWKS endpoint at startup,
// cached in process, and refreshed automatically when an unknown key id
// appears in a token header.
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
// # Multiple issuers (multi-region / multi-tenant / migration)
//
// For a service that accepts tokens from several AuthGates:
//
//	mv, err := jwksauth.NewMultiVerifier(ctx,
//	    []string{"https://auth-a.example.com", "https://auth-b.example.com"},
//	    "https://api.example.com")
//	if err != nil { log.Fatal(err) }
//	// Optional cross-tenant defense — strongly recommended with short tenant codes:
//	if err := mv.SetIssuerTenants("https://auth-a.example.com=oa,hwrd;https://auth-b.example.com=swrd"); err != nil {
//	    log.Fatal(err)
//	}
//	mux.Handle("/api/admin", jwksauth.Middleware(mv, jwksauth.AccessRule{
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
