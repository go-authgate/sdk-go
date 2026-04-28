package jwksauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// fakeIssuer is a minimal in-process OIDC issuer for tests. It serves a
// discovery document, a JWKS endpoint, and exposes Sign() so tests can
// mint tokens. Real JWKS-based verification (signature, iss/aud/exp/nbf)
// runs against it — this is not a stub.
type fakeIssuer struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
	signer jose.Signer
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	kid := fmt.Sprintf("kid-%d", time.Now().UnixNano())
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
	}

	fi := &fakeIssuer{t: t, key: key, kid: kid, signer: signer}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", fi.discovery)
	mux.HandleFunc("/jwks.json", fi.jwks)
	fi.server = httptest.NewServer(mux)
	t.Cleanup(fi.server.Close)
	return fi
}

func (f *fakeIssuer) URL() string { return f.server.URL }

func (f *fakeIssuer) discovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                f.server.URL,
		"jwks_uri":                              f.server.URL + "/jwks.json",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
	})
}

func (f *fakeIssuer) jwks(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	jwk := jose.JSONWebKey{
		Key:       &f.key.PublicKey,
		KeyID:     f.kid,
		Use:       "sig",
		Algorithm: string(jose.RS256),
	}
	_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
}

// Sign issues a JWT with the given claims. ttl<=0 means already-expired;
// audience="" omits the `aud` claim entirely (used to test SkipAudience).
func (f *fakeIssuer) Sign(
	t *testing.T,
	audience string,
	ttl time.Duration,
	extra map[string]any,
) string {
	t.Helper()
	now := time.Now()
	std := map[string]any{
		"iss": f.server.URL,
		"sub": "sub-1",
		"iat": now.Unix(),
		"nbf": now.Add(-30 * time.Second).Unix(),
		"exp": now.Add(ttl).Unix(),
	}
	if audience != "" {
		std["aud"] = audience
	}
	maps.Copy(std, extra)
	raw, err := jwt.Signed(f.signer).Claims(std).Serialize()
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return raw
}

func TestVerifier_HappyPath(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://example")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fi.Sign(t, "api://example", 5*time.Minute, map[string]any{
		"client_id":       "cli",
		"scope":           "email profile",
		"tenant":          "OA",
		"service_account": "sync@oa",
		"project":         "p1",
	})
	info, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if info.Claims.ClientID != "cli" {
		t.Errorf("ClientID = %q", info.Claims.ClientID)
	}
	if !info.HasScope("email") || !info.HasScope("profile") {
		t.Errorf("scopes = %v", info.Scopes)
	}
	if info.Tenant() != "oa" {
		t.Errorf("Tenant() = %q, want lower-cased 'oa'", info.Tenant())
	}
}

func TestNewVerifier_RejectsEmptyAudience(t *testing.T) {
	_, err := NewVerifier(t.Context(), "https://example.com", "")
	if err == nil {
		t.Fatal("expected error for empty audience")
	}
}

func TestVerifierSkipAudience_AcceptsTokenWithoutAud(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifierSkipAudience(t.Context(), fi.URL())
	if err != nil {
		t.Fatalf("NewVerifierSkipAudience: %v", err)
	}
	// Sign a token without an `aud` claim by passing an empty audience.
	tok := fi.Sign(t, "", time.Minute, nil)
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("Verify rejected an aud-less token: %v", err)
	}
}

func TestVerifier_RejectsWrongAudience(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://expected")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fi.Sign(t, "api://other", time.Minute, nil)
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected audience mismatch error")
	}
}

func TestVerifier_RejectsExpired(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://x")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fi.Sign(t, "api://x", -time.Minute, nil)
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected expired error")
	}
}

func TestMiddleware_AuthorizationHeaderHandling(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://x")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tests := []struct {
		name           string
		header         string // empty = no Authorization header at all
		wantStatus     int
		wantWWWAuth    string // exact match if non-empty
		wantWWWAuthSub string // substring match if non-empty
	}{
		// RFC 6750 §3: no credentials supplied → bare Bearer, no error attr.
		{"missing", "", http.StatusUnauthorized, "Bearer", ""},
		{"basic-scheme", "Basic dXNlcjpwYXNz", http.StatusUnauthorized, "Bearer", ""},
		// RFC 6750 §3: credentials supplied for Bearer but malformed →
		// must surface error="invalid_token".
		{"bearer-no-token", "Bearer", http.StatusUnauthorized, "", `error="invalid_token"`},
		{
			"bearer-trailing-junk",
			"Bearer abc def",
			http.StatusUnauthorized,
			"",
			`error="invalid_token"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := runMiddleware(t, v, AccessRule{}, func(req *http.Request) {
				if tc.header != "" {
					req.Header.Set("Authorization", tc.header)
				}
			})
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			got := rec.Header().Get("WWW-Authenticate")
			if tc.wantWWWAuth != "" && got != tc.wantWWWAuth {
				t.Errorf("WWW-Authenticate = %q, want %q", got, tc.wantWWWAuth)
			}
			if tc.wantWWWAuthSub != "" && !strings.Contains(got, tc.wantWWWAuthSub) {
				t.Errorf("WWW-Authenticate %q missing %q", got, tc.wantWWWAuthSub)
			}
		})
	}
}

func TestMiddleware_InvalidToken(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://x")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	rec := runMiddleware(t, v, AccessRule{}, func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer not.a.jwt")
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Errorf("missing invalid_token challenge: %q", rec.Header().Get("WWW-Authenticate"))
	}
}

func TestMiddleware_InsufficientScope(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://x")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fi.Sign(t, "api://x", time.Minute, map[string]any{"scope": "email"})
	rec := runMiddleware(t, v, AccessRule{Scopes: []string{"profile"}}, func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+tok)
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	want := []string{`error="insufficient_scope"`, `scope="profile"`}
	for _, s := range want {
		if !strings.Contains(rec.Header().Get("WWW-Authenticate"), s) {
			t.Errorf("WWW-Authenticate missing %q: %q", s, rec.Header().Get("WWW-Authenticate"))
		}
	}
}

func TestMiddleware_TenantAllowlist(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://x")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tests := []struct {
		name     string
		tenant   string
		rule     []string
		wantCode int
	}{
		// Reject branch (already covered): 401 invalid_token, generic body.
		{"reject", "swrd", []string{"oa"}, http.StatusUnauthorized},
		// Accept branch: case-folded match (rule "OA" matches token "oa").
		{"accept_case_folded", "oa", []string{"OA"}, http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tok := fi.Sign(t, "api://x", time.Minute, map[string]any{"tenant": tc.tenant})
			rec := runMiddleware(t, v, AccessRule{Tenants: tc.rule}, func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer "+tok)
			})
			if rec.Code != tc.wantCode {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantCode)
			}
		})
	}
}

func TestMiddleware_HappyPath_InjectsContext(t *testing.T) {
	fi := newFakeIssuer(t)
	v, err := NewVerifier(t.Context(), fi.URL(), "api://x")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fi.Sign(t, "api://x", time.Minute, map[string]any{
		"scope":  "email",
		"tenant": "OA",
	})
	called := false
	handler := Middleware(v, AccessRule{
		Scopes:  []string{"email"},
		Tenants: []string{"oa"},
	})(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		info, ok := TokenInfoFromContext(r.Context())
		if !ok {
			t.Error("TokenInfoFromContext returned !ok")
			return
		}
		if info.Tenant() != "oa" {
			t.Errorf("Tenant = %q, want oa", info.Tenant())
		}
		called = true
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("inner handler was not called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d", rec.Code)
	}
}

func TestMultiVerifier_RoutesByIssuer(t *testing.T) {
	a := newFakeIssuer(t)
	b := newFakeIssuer(t)
	mv, err := NewMultiVerifier(t.Context(), []string{a.URL(), b.URL()}, "api://x")
	if err != nil {
		t.Fatalf("NewMultiVerifier: %v", err)
	}

	tokA := a.Sign(t, "api://x", time.Minute, map[string]any{"tenant": "oa"})
	infoA, err := mv.Verify(context.Background(), tokA)
	if err != nil {
		t.Fatalf("Verify A: %v", err)
	}
	if infoA.Issuer != a.URL() {
		t.Errorf("issuer = %q, want %q", infoA.Issuer, a.URL())
	}

	tokB := b.Sign(t, "api://x", time.Minute, map[string]any{"tenant": "swrd"})
	infoB, err := mv.Verify(context.Background(), tokB)
	if err != nil {
		t.Fatalf("Verify B: %v", err)
	}
	if infoB.Issuer != b.URL() {
		t.Errorf("issuer = %q, want %q", infoB.Issuer, b.URL())
	}
}

func TestMultiVerifier_RejectsUntrustedIssuer(t *testing.T) {
	a := newFakeIssuer(t)
	b := newFakeIssuer(t) // built but not registered with mv

	mv, err := NewMultiVerifier(t.Context(), []string{a.URL()}, "api://x")
	if err != nil {
		t.Fatalf("NewMultiVerifier: %v", err)
	}
	tok := b.Sign(t, "api://x", time.Minute, nil)
	_, err = mv.Verify(context.Background(), tok)
	if !errors.Is(err, ErrUntrustedIssuer) {
		t.Fatalf("error = %v, want ErrUntrustedIssuer", err)
	}
}

func TestMultiVerifier_CrossTenantDefense(t *testing.T) {
	a := newFakeIssuer(t)
	b := newFakeIssuer(t)
	mv, err := NewMultiVerifier(t.Context(), []string{a.URL(), b.URL()}, "api://x")
	if err != nil {
		t.Fatalf("NewMultiVerifier: %v", err)
	}
	if err := mv.SetIssuerTenants(fmt.Sprintf("%s=oa;%s=swrd", a.URL(), b.URL())); err != nil {
		t.Fatalf("SetIssuerTenants: %v", err)
	}

	// Issuer A claims tenant 'swrd' (which belongs to B) → reject. The
	// error must not echo back the configured allowlist for this issuer.
	tok := a.Sign(t, "api://x", time.Minute, map[string]any{"tenant": "swrd"})
	_, rejErr := mv.Verify(context.Background(), tok)
	if rejErr == nil {
		t.Fatal("expected cross-tenant rejection")
	}
	if strings.Contains(rejErr.Error(), "[oa]") || strings.Contains(rejErr.Error(), "allowed=") {
		t.Errorf("error leaks the allowlist: %v", rejErr)
	}

	// Same issuer, its own tenant → accept.
	tok = a.Sign(t, "api://x", time.Minute, map[string]any{"tenant": "oa"})
	if _, err := mv.Verify(context.Background(), tok); err != nil {
		t.Fatalf("legit token rejected: %v", err)
	}
}

// TestMultiVerifier_SetIssuerTenantsRace exercises the documented contract
// that SetIssuerTenants is safe to call concurrently with Verify (the swap
// is atomic). Run with `go test -race ./jwksauth/`.
func TestMultiVerifier_SetIssuerTenantsRace(t *testing.T) {
	a := newFakeIssuer(t)
	b := newFakeIssuer(t)
	mv, err := NewMultiVerifier(t.Context(), []string{a.URL(), b.URL()}, "api://x")
	if err != nil {
		t.Fatalf("NewMultiVerifier: %v", err)
	}
	tok := a.Sign(t, "api://x", time.Minute, map[string]any{"tenant": "oa"})

	stop := make(chan struct{})
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = mv.Verify(context.Background(), tok)
			}
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		cfg := fmt.Sprintf("%s=oa;%s=swrd", a.URL(), b.URL())
		for i := range 50 {
			if i%2 == 0 {
				_ = mv.SetIssuerTenants(cfg)
			} else {
				_ = mv.SetIssuerTenants("")
			}
		}
	}()

	<-done
	close(stop)
	<-done
}

// runMiddleware wires up a Middleware around a 200-OK inner handler and
// returns the recorded response. modify can mutate the request before send.
func runMiddleware(
	t *testing.T,
	v TokenVerifier,
	rule AccessRule,
	modify func(*http.Request),
) *httptest.ResponseRecorder {
	t.Helper()
	handler := Middleware(v, rule)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if modify != nil {
		modify(req)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}
