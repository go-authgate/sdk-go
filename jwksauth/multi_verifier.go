package jwksauth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

var (
	errAudienceRequiredMulti = errors.New(
		"jwksauth: audience must be non-empty (use NewMultiVerifierSkipAudience to opt out)",
	)
	errIssuerListEmpty   = errors.New("jwksauth: at least one issuer is required")
	errIssuerListTrimmed = errors.New("jwksauth: issuer list is empty after trimming")
)

// MultiVerifier dispatches verification to the right per-issuer verifier
// based on the token's `iss` claim. Discovery is performed concurrently for
// every issuer at construction time; on the hot path the dispatcher is a
// single map lookup followed by the chosen verifier's signature check.
//
// A MultiVerifier is safe for concurrent use after construction. Issuer
// tenant pinning is mutated only via [MultiVerifier.SetIssuerTenants],
// which must be called before the verifier is shared with handlers.
type MultiVerifier struct {
	verifiers map[string]*oidc.IDTokenVerifier

	// issuerTenants pins each issuer to the lower-cased tenant codes it is
	// permitted to sign for. nil = enforcement disabled.
	issuerTenants map[string][]string

	timeout time.Duration
}

// errUntrustedIssuer is the sentinel for tokens whose `iss` claim is not
// in the configured set. Wrap-aware: middleware uses errors.Is to log and
// respond with a generic invalid_token without leaking the issuer set.
var errUntrustedIssuer = errors.New("untrusted issuer")

// ErrUntrustedIssuer is returned by [MultiVerifier.Verify] when the token's
// `iss` claim does not match any configured issuer.
var ErrUntrustedIssuer = errUntrustedIssuer

// NewMultiVerifier builds a multi-issuer verifier. Every issuer in issuers
// must serve a valid OIDC discovery document; discovery happens in parallel
// and is bounded by a single total timeout (default 15s) so one slow issuer
// cannot multiply startup time by N.
//
// audience must be non-empty. Use [NewMultiVerifierSkipAudience] for the
// rare case of issuers that do not emit an `aud` claim on access tokens.
//
// Duplicate issuer URLs in the input are rejected up front. After discovery,
// the canonical issuer string each provider reports (post-normalization) is
// used as the dispatch key — that is what tokens will carry in `iss`.
func NewMultiVerifier(
	ctx context.Context,
	issuers []string,
	audience string,
	opts ...Option,
) (*MultiVerifier, error) {
	if audience == "" {
		return nil, errAudienceRequiredMulti
	}
	return newMultiVerifier(ctx, issuers, audience, false, opts...)
}

// NewMultiVerifierSkipAudience is the audience-opt-out counterpart of
// [NewMultiVerifier]. See [NewVerifierSkipAudience] for the trade-off.
func NewMultiVerifierSkipAudience(
	ctx context.Context,
	issuers []string,
	opts ...Option,
) (*MultiVerifier, error) {
	return newMultiVerifier(ctx, issuers, "", true, opts...)
}

func newMultiVerifier(
	ctx context.Context,
	issuers []string,
	audience string,
	skipAudience bool,
	opts ...Option,
) (*MultiVerifier, error) {
	cleaned, err := dedupIssuers(issuers)
	if err != nil {
		return nil, err
	}
	cfg := defaultVerifierConfig()
	for _, o := range opts {
		if o != nil {
			o.apply(&cfg)
		}
	}

	discoverCtx, cancel := context.WithTimeout(ctx, cfg.discoveryTimeout)
	defer cancel()

	verifiers, err := buildVerifiers(discoverCtx, cleaned, audience, skipAudience)
	if err != nil {
		return nil, err
	}
	return &MultiVerifier{
		verifiers: verifiers,
		timeout:   cfg.verifyTimeout,
	}, nil
}

// SetIssuerTenants enables cross-tenant defense by pinning each issuer to
// the tenant codes it is permitted to sign for. The encoding is:
//
//	iss1=tenantA,tenantB;iss2=tenantC
//
// Every issuer registered with the verifier must appear exactly once in
// raw, and a tenant must be owned by exactly one issuer. Both rules are
// enforced strictly so a typo or operational mistake fails fast at
// configuration time rather than silently disabling the check.
//
// Pass an empty string (or never call this method) to disable cross-tenant
// enforcement — appropriate for single-tenant deployments.
//
// Mutates the receiver; call once during startup before sharing the
// verifier with HTTP handlers.
func (v *MultiVerifier) SetIssuerTenants(raw string) error {
	parsed, err := ParseIssuerTenants(raw, v.Issuers())
	if err != nil {
		return err
	}
	v.issuerTenants = parsed
	return nil
}

// Issuers returns the canonical issuer strings registered with this
// verifier, sorted lexicographically for stable output. Callers may use it
// to log or render configuration; the returned slice is freshly allocated.
func (v *MultiVerifier) Issuers() []string {
	out := make([]string, 0, len(v.verifiers))
	for k := range v.verifiers {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// IssuerTenants returns the configured cross-tenant allowlist keyed by
// canonical issuer, or nil if [MultiVerifier.SetIssuerTenants] was not
// called. The returned map and its slices may be modified by callers
// (a defensive copy is made).
func (v *MultiVerifier) IssuerTenants() map[string][]string {
	if v.issuerTenants == nil {
		return nil
	}
	out := make(map[string][]string, len(v.issuerTenants))
	for k, vs := range v.issuerTenants {
		out[k] = slices.Clone(vs)
	}
	return out
}

// Verify routes raw to the matching per-issuer verifier and returns the
// decoded [TokenInfo] on success.
//
// The flow is:
//  1. Parse the unverified payload to read `iss` (selection only).
//  2. Reject tokens whose iss is not registered ([ErrUntrustedIssuer]).
//  3. Run the chosen verifier, which authoritatively re-checks signature,
//     iss, aud, exp, nbf.
//  4. If [MultiVerifier.SetIssuerTenants] was configured, enforce that
//     this issuer is allowed to sign for the token's tenant.
func (v *MultiVerifier) Verify(ctx context.Context, raw string) (*TokenInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	iss, err := UnverifiedIssuer(raw)
	if err != nil {
		return nil, err
	}
	verifier, ok := v.verifiers[iss]
	if !ok {
		return nil, fmt.Errorf("%w: iss=%q", errUntrustedIssuer, iss)
	}
	tok, err := verifier.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	var extra Claims
	if err := tok.Claims(&extra); err != nil {
		return nil, fmt.Errorf("decode JWT claims: %w", err)
	}
	tenant := strings.ToLower(extra.Tenant)

	if v.issuerTenants != nil {
		// Use tok.Issuer (post-verification) rather than the unverified iss
		// — Verify already proved them equal, but reading the verified value
		// keeps the trust boundary self-evident.
		allowed := v.issuerTenants[tok.Issuer]
		if !slices.Contains(allowed, tenant) {
			return nil, fmt.Errorf(
				"issuer not permitted for this tenant: iss=%q tenant=%q allowed=%v",
				tok.Issuer, extra.Tenant, allowed,
			)
		}
	}

	return &TokenInfo{
		IDToken: tok,
		Claims:  extra,
		Scopes:  strings.Fields(extra.Scope),
		tenant:  tenant,
	}, nil
}

// dedupIssuers trims and validates the input issuer list.
func dedupIssuers(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, errIssuerListEmpty
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, raw := range in {
		iss := strings.TrimSpace(raw)
		if iss == "" {
			continue
		}
		if _, dup := seen[iss]; dup {
			return nil, fmt.Errorf("jwksauth: duplicate issuer in input: %s", iss)
		}
		seen[iss] = struct{}{}
		out = append(out, iss)
	}
	if len(out) == 0 {
		return nil, errIssuerListTrimmed
	}
	return out, nil
}

// buildVerifiers performs OIDC discovery for every trusted issuer in
// parallel. The map is keyed by the canonical issuer string each provider
// reports, since that is what tokens will carry in `iss`.
func buildVerifiers(
	ctx context.Context,
	issuers []string,
	audience string,
	skipAudience bool,
) (map[string]*oidc.IDTokenVerifier, error) {
	type result struct {
		canonical string
		verifier  *oidc.IDTokenVerifier
		err       error
	}
	results := make([]result, len(issuers))

	var wg sync.WaitGroup
	for i, issuer := range issuers {
		wg.Add(1)
		go func(i int, issuer string) {
			defer wg.Done()
			provider, err := oidc.NewProvider(ctx, issuer)
			if err != nil {
				results[i] = result{err: fmt.Errorf("discover %s: %w", issuer, err)}
				return
			}
			var meta struct {
				Issuer string `json:"issuer"`
			}
			if err := provider.Claims(&meta); err != nil {
				results[i] = result{err: fmt.Errorf("read metadata for %s: %w", issuer, err)}
				return
			}
			results[i] = result{
				canonical: meta.Issuer,
				verifier: provider.Verifier(&oidc.Config{
					ClientID:          audience,
					SkipClientIDCheck: skipAudience,
				}),
			}
		}(i, issuer)
	}
	wg.Wait()

	out := make(map[string]*oidc.IDTokenVerifier, len(issuers))
	for _, r := range results {
		if r.err != nil {
			return nil, r.err
		}
		if _, dup := out[r.canonical]; dup {
			return nil, fmt.Errorf(
				"duplicate issuer in TRUSTED_ISSUERS after discovery: %s",
				r.canonical,
			)
		}
		out[r.canonical] = r.verifier
	}
	return out, nil
}
