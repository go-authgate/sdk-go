// Package discovery provides OIDC auto-discovery from /.well-known/openid-configuration.
//
// It fetches and caches the provider metadata, making all endpoint URLs
// available without manual configuration.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	retry "github.com/appleboy/go-httpretry"

	"github.com/go-authgate/sdk-go/oauth"
)

const (
	wellKnownPath   = "/.well-known/openid-configuration"
	defaultCacheTTL = 1 * time.Hour
)

// Metadata represents a subset of the OIDC Provider Metadata (RFC 8414)
// tailored to the fields used by the AuthGate SDK.
type Metadata struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint,omitempty"`
	RevocationEndpoint               string   `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint            string   `json:"introspection_endpoint,omitempty"`
	DeviceAuthorizationEndpoint      string   `json:"device_authorization_endpoint,omitempty"`
	ResponseTypesSupported           []string `json:"response_types_supported,omitempty"`
	SubjectTypesSupported            []string `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ScopesSupported                  []string `json:"scopes_supported,omitempty"`
	TokenEndpointAuthMethods         []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	GrantTypesSupported              []string `json:"grant_types_supported,omitempty"`
	ClaimsSupported                  []string `json:"claims_supported,omitempty"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported,omitempty"`
}

// Endpoints converts the metadata to an oauth.Endpoints struct.
func (m *Metadata) Endpoints() oauth.Endpoints {
	ep := oauth.Endpoints{
		TokenURL:               m.TokenEndpoint,
		AuthorizeURL:           m.AuthorizationEndpoint,
		RevocationURL:          m.RevocationEndpoint,
		IntrospectionURL:       m.IntrospectionEndpoint,
		UserinfoURL:            m.UserinfoEndpoint,
		DeviceAuthorizationURL: m.DeviceAuthorizationEndpoint,
	}

	// TokenInfoURL is always derived from issuer (not part of standard OIDC discovery)
	if m.Issuer != "" {
		ep.TokenInfoURL = strings.TrimRight(m.Issuer, "/") + "/oauth/tokeninfo"
	}

	return ep
}

// Client is an OIDC discovery client with caching.
type Client struct {
	issuerURL  string
	httpClient *retry.Client
	cacheTTL   time.Duration

	mu        sync.RWMutex
	cached    *Metadata
	fetchedAt time.Time
}

// Option configures a discovery Client.
type Option func(*Client)

// WithHTTPClient sets a custom retry HTTP client.
// If nil is provided, the default client is kept.
func WithHTTPClient(httpClient *retry.Client) Option {
	return func(c *Client) {
		if httpClient != nil {
			c.httpClient = httpClient
		}
	}
}

// WithCacheTTL sets the cache time-to-live for discovery metadata.
func WithCacheTTL(ttl time.Duration) Option {
	return func(c *Client) {
		c.cacheTTL = ttl
	}
}

// NewClient creates a new OIDC discovery client.
func NewClient(issuerURL string, opts ...Option) (*Client, error) {
	httpClient, err := retry.NewRealtimeClient(retry.WithNoLogging())
	if err != nil {
		return nil, fmt.Errorf("discovery: create http client: %w", err)
	}

	c := &Client{
		issuerURL:  strings.TrimRight(issuerURL, "/"),
		httpClient: httpClient,
		cacheTTL:   defaultCacheTTL,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c, nil
}

// Fetch retrieves the OIDC provider metadata, using the cache if still valid.
// The returned Metadata is a copy; callers may safely modify it without
// affecting the cached value.
func (c *Client) Fetch(ctx context.Context) (*Metadata, error) {
	c.mu.RLock()
	if c.cached != nil && time.Since(c.fetchedAt) < c.cacheTTL {
		cp := *c.cached
		c.mu.RUnlock()
		return &cp, nil
	}
	c.mu.RUnlock()

	return c.refresh(ctx)
}

// refresh fetches fresh metadata from the discovery endpoint.
func (c *Client) refresh(ctx context.Context) (*Metadata, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if c.cached != nil && time.Since(c.fetchedAt) < c.cacheTTL {
		cp := *c.cached
		return &cp, nil
	}

	discoveryURL := c.issuerURL + wellKnownPath
	resp, err := c.httpClient.Get(ctx, discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("discovery: fetch %s: %w", discoveryURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"discovery: unexpected status %d from %s",
			resp.StatusCode,
			discoveryURL,
		)
	}

	var meta Metadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("discovery: decode response: %w", err)
	}

	// Validate issuer matches the expected URL (OIDC Discovery 1.0 §4.3)
	returnedIssuer := strings.TrimRight(meta.Issuer, "/")
	if returnedIssuer != c.issuerURL {
		return nil, fmt.Errorf(
			"discovery: issuer mismatch: got %q, expected %q",
			meta.Issuer,
			c.issuerURL,
		)
	}

	// AuthGate returns /oauth/device/code as device_authorization_endpoint via the
	// standard OIDC discovery. If it's not set explicitly, derive it from grant types.
	if meta.DeviceAuthorizationEndpoint == "" && meta.Issuer != "" {
		if slices.Contains(
			meta.GrantTypesSupported,
			"urn:ietf:params:oauth:grant-type:device_code",
		) {
			meta.DeviceAuthorizationEndpoint = strings.TrimRight(
				meta.Issuer,
				"/",
			) + "/oauth/device/code"
		}
	}

	// AuthGate has /oauth/introspect but doesn't yet advertise it in discovery
	if meta.IntrospectionEndpoint == "" && meta.Issuer != "" {
		meta.IntrospectionEndpoint = strings.TrimRight(meta.Issuer, "/") + "/oauth/introspect"
	}

	c.cached = &meta
	c.fetchedAt = time.Now()

	cp := meta
	return &cp, nil
}
