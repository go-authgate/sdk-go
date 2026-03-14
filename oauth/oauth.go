// Package oauth provides an OAuth 2.0 token client for AuthGate.
//
// It encapsulates all HTTP request/response logic for Device Code,
// Authorization Code + PKCE, Client Credentials, Refresh, Revoke,
// Introspect, and UserInfo flows. This is a pure HTTP client layer
// that does not handle storage, polling, or UI interactions.
package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	retry "github.com/appleboy/go-httpretry"
)

// Token represents an OAuth 2.0 token response (RFC 6749 §5.1).
type Token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`

	// ExpiresAt is computed from ExpiresIn at response parse time.
	ExpiresAt time.Time `json:"-"`
}

// IsExpired reports whether the token has expired.
func (t *Token) IsExpired() bool {
	return !t.ExpiresAt.IsZero() && time.Now().After(t.ExpiresAt)
}

// IsValid reports whether the token has a non-empty access token and is not expired.
func (t *Token) IsValid() bool {
	return t.AccessToken != "" && !t.IsExpired()
}

// DeviceAuth represents a device authorization response (RFC 8628 §3.2).
type DeviceAuth struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// IntrospectionResult represents a token introspection response (RFC 7662 §2.2).
type IntrospectionResult struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Iss       string `json:"iss,omitempty"`
	Jti       string `json:"jti,omitempty"`
}

// UserInfo represents the OIDC UserInfo response (OIDC Core 1.0 §5.3).
type UserInfo struct {
	Sub               string `json:"sub"`
	Iss               string `json:"iss,omitempty"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Picture           string `json:"picture,omitempty"`
	UpdatedAt         int64  `json:"updated_at,omitempty"`
	SubjectType       string `json:"subject_type,omitempty"`
}

// TokenInfo represents the tokeninfo response from AuthGate.
type TokenInfo struct {
	Active      bool   `json:"active"`
	UserID      string `json:"user_id"`
	ClientID    string `json:"client_id"`
	Scope       string `json:"scope"`
	Exp         int64  `json:"exp"`
	Iss         string `json:"iss"`
	SubjectType string `json:"subject_type"`
}

// Error represents an OAuth 2.0 error response (RFC 6749 §5.2).
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	StatusCode  int    `json:"-"`
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("oauth: %s: %s", e.Code, e.Description)
	}
	return "oauth: " + e.Code
}

// Endpoints holds all OAuth 2.0 endpoint URLs.
type Endpoints struct {
	TokenURL               string
	AuthorizeURL           string
	DeviceAuthorizationURL string
	RevocationURL          string
	IntrospectionURL       string
	UserinfoURL            string
	TokenInfoURL           string
}

// Client is an OAuth 2.0 HTTP client.
type Client struct {
	clientID     string
	clientSecret string
	endpoints    Endpoints
	httpClient   *retry.Client
}

// Option configures a Client.
type Option func(*Client)

// WithClientSecret sets the client secret for confidential clients.
func WithClientSecret(secret string) Option {
	return func(c *Client) {
		c.clientSecret = secret
	}
}

// WithHTTPClient sets a custom retry HTTP client.
func WithHTTPClient(httpClient *retry.Client) Option {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

// NewClient creates a new OAuth 2.0 client.
func NewClient(clientID string, endpoints Endpoints, opts ...Option) (*Client, error) {
	httpClient, err := retry.NewRealtimeClient(retry.WithNoLogging())
	if err != nil {
		return nil, fmt.Errorf("oauth: create http client: %w", err)
	}

	c := &Client{
		clientID:   clientID,
		endpoints:  endpoints,
		httpClient: httpClient,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// ClientID returns the client ID.
func (c *Client) ClientID() string {
	return c.clientID
}

// Endpoints returns the endpoint URLs.
func (c *Client) Endpoints() Endpoints {
	return c.endpoints
}

// RequestDeviceCode initiates a device authorization request (RFC 8628 §3.1).
func (c *Client) RequestDeviceCode(ctx context.Context, scopes []string) (*DeviceAuth, error) {
	if c.endpoints.DeviceAuthorizationURL == "" {
		return nil, &Error{
			Code:        "invalid_request",
			Description: "device authorization endpoint not configured",
		}
	}

	data := url.Values{
		"client_id": {c.clientID},
		"scope":     {strings.Join(scopes, " ")},
	}

	var auth DeviceAuth
	if err := c.postForm(ctx, c.endpoints.DeviceAuthorizationURL, data, &auth); err != nil {
		return nil, err
	}
	return &auth, nil
}

// ExchangeDeviceCode exchanges a device code for tokens (RFC 8628 §3.4).
func (c *Client) ExchangeDeviceCode(ctx context.Context, deviceCode string) (*Token, error) {
	data := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {c.clientID},
	}

	return c.tokenRequest(ctx, data)
}

// ExchangeAuthCode exchanges an authorization code for tokens (RFC 6749 §4.1.3).
func (c *Client) ExchangeAuthCode(
	ctx context.Context,
	code, redirectURI, codeVerifier string,
) (*Token, error) {
	data := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {c.clientID},
	}

	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}
	if c.clientSecret != "" {
		data.Set("client_secret", c.clientSecret)
	}

	return c.tokenRequest(ctx, data)
}

// ClientCredentials requests a token using client credentials (RFC 6749 §4.4).
func (c *Client) ClientCredentials(ctx context.Context, scopes []string) (*Token, error) {
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}
	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}

	return c.tokenRequest(ctx, data)
}

// RefreshToken exchanges a refresh token for new tokens (RFC 6749 §6).
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {c.clientID},
	}

	return c.tokenRequest(ctx, data)
}

// Revoke revokes a token (RFC 7009).
func (c *Client) Revoke(ctx context.Context, token string) error {
	if c.endpoints.RevocationURL == "" {
		return &Error{Code: "invalid_request", Description: "revocation endpoint not configured"}
	}

	data := url.Values{
		"token": {token},
	}

	resp, err := c.httpClient.Post(ctx, c.endpoints.RevocationURL,
		retry.WithBody("application/x-www-form-urlencoded", strings.NewReader(data.Encode())),
	)
	if err != nil {
		return fmt.Errorf("oauth: revoke request: %w", err)
	}
	defer resp.Body.Close()

	// RFC 7009: always returns 200
	return nil
}

// Introspect introspects a token (RFC 7662).
func (c *Client) Introspect(ctx context.Context, token string) (*IntrospectionResult, error) {
	if c.endpoints.IntrospectionURL == "" {
		return nil, &Error{
			Code:        "invalid_request",
			Description: "introspection endpoint not configured",
		}
	}

	data := url.Values{
		"token":         {token},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}

	var result IntrospectionResult
	if err := c.postForm(ctx, c.endpoints.IntrospectionURL, data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UserInfo fetches user information from the UserInfo endpoint (OIDC Core 1.0 §5.3).
func (c *Client) UserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	if c.endpoints.UserinfoURL == "" {
		return nil, &Error{Code: "invalid_request", Description: "userinfo endpoint not configured"}
	}

	resp, err := c.httpClient.Get(ctx, c.endpoints.UserinfoURL,
		retry.WithHeader("Authorization", "Bearer "+accessToken),
	)
	if err != nil {
		return nil, fmt.Errorf("oauth: userinfo request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResponse(resp)
	}

	var info UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("oauth: decode userinfo response: %w", err)
	}
	return &info, nil
}

// TokenInfoRequest fetches token information from the tokeninfo endpoint.
func (c *Client) TokenInfoRequest(ctx context.Context, accessToken string) (*TokenInfo, error) {
	if c.endpoints.TokenInfoURL == "" {
		return nil, &Error{
			Code:        "invalid_request",
			Description: "tokeninfo endpoint not configured",
		}
	}

	resp, err := c.httpClient.Get(ctx, c.endpoints.TokenInfoURL,
		retry.WithHeader("Authorization", "Bearer "+accessToken),
	)
	if err != nil {
		return nil, fmt.Errorf("oauth: tokeninfo request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResponse(resp)
	}

	var info TokenInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("oauth: decode tokeninfo response: %w", err)
	}
	return &info, nil
}

// tokenRequest sends a token request and parses the response.
func (c *Client) tokenRequest(ctx context.Context, data url.Values) (*Token, error) {
	if c.endpoints.TokenURL == "" {
		return nil, &Error{Code: "invalid_request", Description: "token endpoint not configured"}
	}

	var tok Token
	if err := c.postForm(ctx, c.endpoints.TokenURL, data, &tok); err != nil {
		return nil, err
	}

	// Compute ExpiresAt from ExpiresIn
	if tok.ExpiresIn > 0 {
		tok.ExpiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	}

	return &tok, nil
}

// postForm sends a POST request with form-encoded body and decodes the JSON response.
func (c *Client) postForm(ctx context.Context, endpoint string, data url.Values, result any) error {
	resp, err := c.httpClient.Post(ctx, endpoint,
		retry.WithBody("application/x-www-form-urlencoded", strings.NewReader(data.Encode())),
	)
	if err != nil {
		return fmt.Errorf("oauth: request to %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return parseErrorResponse(resp)
	}

	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return fmt.Errorf("oauth: decode response from %s: %w", endpoint, err)
	}
	return nil
}

// parseErrorResponse reads an OAuth error response body.
func parseErrorResponse(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &Error{
			Code:        "server_error",
			Description: "failed to read error response",
			StatusCode:  resp.StatusCode,
		}
	}

	var oauthErr Error
	if json.Unmarshal(body, &oauthErr) == nil && oauthErr.Code != "" {
		oauthErr.StatusCode = resp.StatusCode
		return &oauthErr
	}

	return &Error{
		Code:        http.StatusText(resp.StatusCode),
		Description: string(body),
		StatusCode:  resp.StatusCode,
	}
}
