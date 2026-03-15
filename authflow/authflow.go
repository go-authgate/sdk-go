// Package authflow provides high-level CLI authentication flow orchestration.
//
// It handles Device Code polling, Authorization Code + PKCE with a local
// callback server and browser opening, and automatic token refresh with
// persistent storage via credstore.
package authflow

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/go-authgate/sdk-go/credstore"
	"github.com/go-authgate/sdk-go/oauth"
)

// DeviceFlowHandler is called to display the device code to the user.
type DeviceFlowHandler interface {
	DisplayCode(auth *oauth.DeviceAuth) error
}

// DefaultDeviceFlowHandler prints the user code and verification URI to stdout.
type DefaultDeviceFlowHandler struct{}

// DisplayCode prints instructions for the user.
func (h DefaultDeviceFlowHandler) DisplayCode(auth *oauth.DeviceAuth) error {
	fmt.Printf(
		"Open %s in your browser and enter code: %s\n",
		auth.VerificationURI,
		auth.UserCode,
	)
	return nil
}

// DeviceFlowOption configures RunDeviceFlow.
type DeviceFlowOption func(*deviceFlowConfig)

type deviceFlowConfig struct {
	handler     DeviceFlowHandler
	openBrowser bool
}

// WithDeviceFlowHandler sets a custom handler for displaying the device code.
func WithDeviceFlowHandler(h DeviceFlowHandler) DeviceFlowOption {
	return func(cfg *deviceFlowConfig) {
		cfg.handler = h
	}
}

// WithOpenBrowser controls whether to automatically open the verification URI.
func WithOpenBrowser(open bool) DeviceFlowOption {
	return func(cfg *deviceFlowConfig) {
		cfg.openBrowser = open
	}
}

// RunDeviceFlow executes the complete Device Code flow (RFC 8628):
// request device code, display user code, poll for token.
func RunDeviceFlow(
	ctx context.Context,
	client *oauth.Client,
	scopes []string,
	opts ...DeviceFlowOption,
) (*oauth.Token, error) {
	cfg := &deviceFlowConfig{
		handler: DefaultDeviceFlowHandler{},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}

	auth, err := client.RequestDeviceCode(ctx, scopes)
	if err != nil {
		return nil, fmt.Errorf("authflow: request device code: %w", err)
	}

	if err := cfg.handler.DisplayCode(auth); err != nil {
		return nil, fmt.Errorf("authflow: display code: %w", err)
	}

	if cfg.openBrowser {
		uri := auth.VerificationURIComplete
		if uri == "" {
			uri = auth.VerificationURI
		}
		_ = openBrowser(uri)
	}

	return pollDeviceCode(ctx, client, auth)
}

// pollDeviceCode polls the token endpoint until the user authorizes or the code expires.
func pollDeviceCode(
	ctx context.Context,
	client *oauth.Client,
	auth *oauth.DeviceAuth,
) (*oauth.Token, error) {
	interval := time.Duration(auth.Interval) * time.Second
	if interval < 1*time.Second {
		interval = 5 * time.Second
	}

	deadline := time.Now().Add(time.Duration(auth.ExpiresIn) * time.Second)
	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		if time.Now().After(deadline) {
			return nil, errors.New("authflow: device code expired")
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}

		token, err := client.ExchangeDeviceCode(ctx, auth.DeviceCode)
		if err != nil {
			var oauthErr *oauth.Error
			if errors.As(err, &oauthErr) {
				switch oauthErr.Code {
				case "authorization_pending":
					timer.Reset(interval)
					continue
				case "slow_down":
					interval += 5 * time.Second
					timer.Reset(interval)
					continue
				case "expired_token":
					return nil, errors.New("authflow: device code expired")
				case "access_denied":
					return nil, errors.New("authflow: access denied by user")
				}
			}
			return nil, fmt.Errorf("authflow: exchange device code: %w", err)
		}

		return token, nil
	}
}

// generateState produces a cryptographically random state string for CSRF protection.
func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// AuthCodeFlowOption configures RunAuthCodeFlow.
type AuthCodeFlowOption func(*authCodeFlowConfig)

type authCodeFlowConfig struct {
	localPort int // 0 means pick a random free port
}

// WithLocalPort sets the local port for the callback server.
// By default a random free port is used.
func WithLocalPort(port int) AuthCodeFlowOption {
	return func(cfg *authCodeFlowConfig) {
		cfg.localPort = port
	}
}

// RunAuthCodeFlow executes the Authorization Code + PKCE flow:
// generate PKCE + state, start local callback server, open browser, exchange code.
func RunAuthCodeFlow(
	ctx context.Context,
	client *oauth.Client,
	scopes []string,
	opts ...AuthCodeFlowOption,
) (*oauth.Token, error) {
	cfg := &authCodeFlowConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	pkce, err := NewPKCE()
	if err != nil {
		return nil, fmt.Errorf("authflow: generate PKCE: %w", err)
	}

	state, err := generateState()
	if err != nil {
		return nil, fmt.Errorf("authflow: generate state: %w", err)
	}

	// Start the callback server on the configured (or random) port
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.localPort))
	if err != nil {
		return nil, fmt.Errorf("authflow: listen: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	// Use sync.Once to ensure only the first callback is processed.
	// Browser retries or user refreshes are safely ignored.
	var once sync.Once
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() {
			// Validate state parameter for CSRF protection
			if r.URL.Query().Get("state") != state {
				errCh <- &oauth.Error{
					Code:        "invalid_state",
					Description: "State parameter mismatch",
				}
				fmt.Fprint(
					w,
					"<html><body><h1>Authentication failed</h1><p>State mismatch. You can close this window.</p></body></html>",
				)
				return
			}

			code := r.URL.Query().Get("code")
			if code == "" {
				errMsg := r.URL.Query().Get("error")
				errDesc := r.URL.Query().Get("error_description")
				if errMsg == "" {
					errMsg = "no code received"
				}
				errCh <- &oauth.Error{Code: errMsg, Description: errDesc}
				fmt.Fprint(
					w,
					"<html><body><h1>Authentication failed</h1><p>You can close this window.</p></body></html>",
				)
				return
			}
			codeCh <- code
			fmt.Fprint(
				w,
				"<html><body><h1>Authentication successful</h1><p>You can close this window.</p></body></html>",
			)
		})
	})

	server := &http.Server{Handler: mux}

	var wg sync.WaitGroup
	wg.Go(func() {
		if srvErr := server.Serve(
			listener,
		); srvErr != nil &&
			!errors.Is(srvErr, http.ErrServerClosed) {
			errCh <- fmt.Errorf("authflow: callback server: %w", srvErr)
		}
	})

	// Build authorization URL
	endpoints := client.Endpoints()
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {client.ClientID()},
		"redirect_uri":          {redirectURI},
		"scope":                 {joinScopes(scopes)},
		"state":                 {state},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {pkce.Method},
	}
	authURL := endpoints.AuthorizeURL + "?" + params.Encode()

	if err := openBrowser(authURL); err != nil {
		fmt.Printf("Open this URL in your browser:\n%s\n", authURL)
	}

	// Wait for callback or timeout
	var code string
	select {
	case code = <-codeCh:
	case err := <-errCh:
		_ = server.Shutdown(ctx)
		wg.Wait()
		return nil, err
	case <-ctx.Done():
		_ = server.Shutdown(ctx)
		wg.Wait()
		return nil, ctx.Err()
	}

	_ = server.Shutdown(ctx)
	wg.Wait()

	// Exchange code for token
	token, err := client.ExchangeAuthCode(ctx, code, redirectURI, pkce.Verifier)
	if err != nil {
		return nil, fmt.Errorf("authflow: exchange auth code: %w", err)
	}
	return token, nil
}

// TokenSourceOption configures a TokenSource.
type TokenSourceOption func(*TokenSource)

// WithStore sets the credential store for token persistence.
func WithStore(store credstore.Store[credstore.Token]) TokenSourceOption {
	return func(ts *TokenSource) {
		ts.store = store
	}
}

// TokenSource provides automatic token refresh with optional persistent storage.
// Concurrent callers share a single in-flight refresh request via singleflight.
type TokenSource struct {
	client *oauth.Client
	store  credstore.Store[credstore.Token]
	mu     sync.RWMutex
	group  singleflight.Group
}

// NewTokenSource creates a new TokenSource that automatically refreshes tokens.
func NewTokenSource(client *oauth.Client, opts ...TokenSourceOption) *TokenSource {
	ts := &TokenSource{
		client: client,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(ts)
		}
	}
	return ts
}

// Token returns a valid token, refreshing from store or server as needed.
// Concurrent callers share a single in-flight refresh request via singleflight.
func (ts *TokenSource) Token(ctx context.Context) (*oauth.Token, error) {
	// Fast path: read-lock to check for a valid cached token
	if ts.store != nil {
		ts.mu.RLock()
		stored, err := ts.store.Load(ts.client.ClientID())
		ts.mu.RUnlock()
		if err == nil && stored.IsValid() {
			return credstoreToOAuth(&stored), nil
		}
	}

	// Slow path: use singleflight to coalesce concurrent refresh requests
	v, err, _ := ts.group.Do("token", func() (any, error) {
		// Re-check after acquiring the singleflight slot
		if ts.store != nil {
			ts.mu.RLock()
			stored, err := ts.store.Load(ts.client.ClientID())
			ts.mu.RUnlock()
			if err == nil && stored.IsValid() {
				return credstoreToOAuth(&stored), nil
			}

			if err != nil && !errors.Is(err, credstore.ErrNotFound) {
				return nil, fmt.Errorf("authflow: load token: %w", err)
			}

			// Try refreshing if we have a refresh token
			if err == nil && stored.RefreshToken != "" {
				refreshed, refreshErr := ts.client.RefreshToken(ctx, stored.RefreshToken)
				if refreshErr != nil {
					return nil, fmt.Errorf("authflow: refresh token: %w", refreshErr)
				}

				ts.mu.Lock()
				saveErr := ts.saveToken(refreshed)
				ts.mu.Unlock()
				if saveErr != nil {
					return nil, fmt.Errorf("authflow: save refreshed token: %w", saveErr)
				}
				return refreshed, nil
			}
		}

		return nil, errors.New("authflow: no valid token available, re-authentication required")
	})
	if err != nil {
		return nil, err
	}

	return v.(*oauth.Token), nil
}

// SaveToken persists a token to the store (if configured).
func (ts *TokenSource) SaveToken(token *oauth.Token) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	return ts.saveToken(token)
}

func (ts *TokenSource) saveToken(token *oauth.Token) error {
	if ts.store == nil {
		return nil
	}
	return ts.store.Save(ts.client.ClientID(), oauthToCredstore(token, ts.client.ClientID()))
}

func credstoreToOAuth(t *credstore.Token) *oauth.Token {
	return &oauth.Token{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		TokenType:    t.TokenType,
		ExpiresAt:    t.ExpiresAt,
	}
}

func oauthToCredstore(t *oauth.Token, clientID string) credstore.Token {
	return credstore.Token{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		TokenType:    t.TokenType,
		ExpiresAt:    t.ExpiresAt,
		ClientID:     clientID,
	}
}

func joinScopes(scopes []string) string {
	return strings.Join(scopes, " ")
}

// openBrowser opens a URL in the default browser.
func openBrowser(rawURL string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", rawURL).Start()
	case "linux":
		return exec.Command("xdg-open", rawURL).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL).Start()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// CheckBrowserAvailability checks whether a browser can be opened.
// Returns false in SSH sessions or environments without a display.
func CheckBrowserAvailability() bool {
	// Detect SSH sessions across all platforms
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != "" {
		return false
	}

	switch runtime.GOOS {
	case "darwin":
		return true
	case "linux":
		if _, err := exec.LookPath("xdg-open"); err != nil {
			return false
		}
		// Require a display server (X11 or Wayland)
		return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
	case "windows":
		return true
	default:
		return false
	}
}
