// Package authgate provides a one-call entry point for authenticating with
// an AuthGate server and obtaining an OAuth token.
package authgate

import (
	"context"
	"fmt"

	"github.com/go-authgate/sdk-go/authflow"
	"github.com/go-authgate/sdk-go/credstore"
	"github.com/go-authgate/sdk-go/discovery"
	"github.com/go-authgate/sdk-go/oauth"
)

// FlowMode controls the authentication flow selection strategy.
type FlowMode int

const (
	// FlowModeAuto detects browser availability: uses AuthCode if available, Device otherwise.
	FlowModeAuto FlowMode = iota
	// FlowModeBrowser forces Authorization Code + PKCE flow.
	FlowModeBrowser
	// FlowModeDevice forces Device Code flow.
	FlowModeDevice
)

type config struct {
	scopes      []string
	serviceName string
	storePath   string
	localPort   int
	flowMode    FlowMode
}

// Option configures the New function.
type Option func(*config)

// WithScopes sets the OAuth scopes to request.
func WithScopes(scopes ...string) Option {
	return func(cfg *config) {
		cfg.scopes = scopes
	}
}

// WithServiceName sets the keyring service name for token storage.
func WithServiceName(name string) Option {
	return func(cfg *config) {
		cfg.serviceName = name
	}
}

// WithStorePath sets the file fallback path for token storage.
func WithStorePath(path string) Option {
	return func(cfg *config) {
		cfg.storePath = path
	}
}

// WithLocalPort sets the local redirect port for the Authorization Code flow.
func WithLocalPort(port int) Option {
	return func(cfg *config) {
		cfg.localPort = port
	}
}

// WithFlowMode specifies which authentication flow to use.
func WithFlowMode(mode FlowMode) Option {
	return func(cfg *config) {
		cfg.flowMode = mode
	}
}

// New authenticates with the AuthGate server and returns a ready-to-use OAuth
// client and token. Cached tokens are reused automatically; expired tokens are
// refreshed. When no valid token exists, the flow is determined by flowMode.
//
//	client, token, err := authgate.New(ctx,
//	    os.Getenv("AUTHGATE_URL"),
//	    os.Getenv("CLIENT_ID"),
//	    authgate.WithScopes("profile", "email"),
//	)
func New(ctx context.Context, authgateURL, clientID string, opts ...Option) (*oauth.Client, *oauth.Token, error) {
	if authgateURL == "" {
		return nil, nil, fmt.Errorf("authgate: authgateURL is required")
	}
	if clientID == "" {
		return nil, nil, fmt.Errorf("authgate: clientID is required")
	}

	cfg := &config{
		scopes:      []string{},
		serviceName: "authgate",
		storePath:   ".authgate-tokens.json",
		localPort:   8088,
		flowMode:    FlowModeAuto,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}

	// 1. Discover endpoints
	disco, err := discovery.NewClient(authgateURL)
	if err != nil {
		return nil, nil, fmt.Errorf("authgate: discovery client: %w", err)
	}
	meta, err := disco.Fetch(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("authgate: fetch discovery: %w", err)
	}

	// 2. Create OAuth client
	client, err := oauth.NewClient(clientID, meta.Endpoints())
	if err != nil {
		return nil, nil, fmt.Errorf("authgate: oauth client: %w", err)
	}

	// 3. Set up token store and source
	store := credstore.DefaultTokenSecureStore(cfg.serviceName, cfg.storePath)
	ts := authflow.NewTokenSource(client, authflow.WithStore(store))

	// 4. Return cached/refreshed token if available
	token, err := ts.Token(ctx)
	if err == nil {
		return client, token, nil
	}

	// 5. No valid token — run the appropriate authentication flow
	switch cfg.flowMode {
	case FlowModeBrowser:
		token, err = authflow.RunAuthCodeFlow(ctx, client, cfg.scopes,
			authflow.WithLocalPort(cfg.localPort),
		)
	case FlowModeDevice:
		token, err = authflow.RunDeviceFlow(ctx, client, cfg.scopes)
	default: // FlowModeAuto
		if authflow.CheckBrowserAvailability() {
			token, err = authflow.RunAuthCodeFlow(ctx, client, cfg.scopes,
				authflow.WithLocalPort(cfg.localPort),
			)
		} else {
			token, err = authflow.RunDeviceFlow(ctx, client, cfg.scopes)
		}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("authgate: authenticate: %w", err)
	}

	// 6. Persist the new token
	if saveErr := ts.SaveToken(token); saveErr != nil {
		return nil, nil, fmt.Errorf("authgate: save token: %w", saveErr)
	}

	return client, token, nil
}
