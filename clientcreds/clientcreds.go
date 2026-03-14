// Package clientcreds provides a thread-safe TokenSource for the
// OAuth 2.0 Client Credentials grant (RFC 6749 §4.4).
//
// It automatically caches tokens and refreshes them before expiry,
// making it ideal for service-to-service (M2M) authentication.
package clientcreds

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-authgate/sdk-go/oauth"
)

const defaultExpiryDelta = 30 * time.Second

// Option configures a TokenSource.
type Option func(*TokenSource)

// WithScopes sets the scopes to request.
func WithScopes(scopes ...string) Option {
	return func(ts *TokenSource) {
		ts.scopes = scopes
	}
}

// WithExpiryDelta sets how early before expiry to refresh the token.
func WithExpiryDelta(d time.Duration) Option {
	return func(ts *TokenSource) {
		ts.expiryDelta = d
	}
}

// TokenSource is a thread-safe, auto-caching token source for client credentials.
type TokenSource struct {
	client      *oauth.Client
	scopes      []string
	expiryDelta time.Duration

	mu    sync.Mutex
	token *oauth.Token
}

// NewTokenSource creates a new client credentials TokenSource.
func NewTokenSource(client *oauth.Client, opts ...Option) *TokenSource {
	ts := &TokenSource{
		client:      client,
		expiryDelta: defaultExpiryDelta,
	}
	for _, opt := range opts {
		opt(ts)
	}
	return ts
}

// Token returns a valid access token, fetching a new one if the cached token
// is expired or about to expire.
func (ts *TokenSource) Token(ctx context.Context) (*oauth.Token, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.token != nil && ts.isValid() {
		return ts.token, nil
	}

	token, err := ts.client.ClientCredentials(ctx, ts.scopes)
	if err != nil {
		return nil, fmt.Errorf("clientcreds: fetch token: %w", err)
	}

	ts.token = token
	return token, nil
}

// isValid reports whether the cached token is still usable.
// Must be called with ts.mu held.
func (ts *TokenSource) isValid() bool {
	if ts.token == nil || ts.token.AccessToken == "" {
		return false
	}
	if ts.token.ExpiresAt.IsZero() {
		return true
	}
	return time.Now().Add(ts.expiryDelta).Before(ts.token.ExpiresAt)
}

// HTTPClient returns an *http.Client that automatically attaches a valid
// Bearer token to every request.
func (ts *TokenSource) HTTPClient() *http.Client {
	return &http.Client{
		Transport: ts.RoundTripper(http.DefaultTransport),
	}
}

// RoundTripper returns an http.RoundTripper that attaches a Bearer token
// to every request. It wraps the given base transport.
func (ts *TokenSource) RoundTripper(base http.RoundTripper) http.RoundTripper {
	return &tokenTransport{
		source: ts,
		base:   base,
	}
}

type tokenTransport struct {
	source *TokenSource
	base   http.RoundTripper
}

func (t *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.source.Token(req.Context())
	if err != nil {
		return nil, fmt.Errorf("clientcreds: get token for request: %w", err)
	}

	// Clone the request to avoid mutating the original
	r2 := req.Clone(req.Context())
	r2.Header.Set("Authorization", "Bearer "+token.AccessToken)
	return t.base.RoundTrip(r2)
}
