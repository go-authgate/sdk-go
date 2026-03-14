package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func setupTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Client) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	endpoints := Endpoints{
		TokenURL:               server.URL + "/oauth/token",
		AuthorizeURL:           server.URL + "/oauth/authorize",
		DeviceAuthorizationURL: server.URL + "/oauth/device/code",
		RevocationURL:          server.URL + "/oauth/revoke",
		IntrospectionURL:       server.URL + "/oauth/introspect",
		UserinfoURL:            server.URL + "/oauth/userinfo",
		TokenInfoURL:           server.URL + "/oauth/tokeninfo",
	}

	client, err := NewClient("test-client", endpoints)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return server, client
}

func TestRequestDeviceCode(t *testing.T) {
	_, client := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/device/code" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}

		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if r.PostForm.Get("client_id") != "test-client" {
			t.Errorf("unexpected client_id: %s", r.PostForm.Get("client_id"))
		}
		if r.PostForm.Get("scope") != "read write" {
			t.Errorf("unexpected scope: %s", r.PostForm.Get("scope"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"device_code":               "dev-code-123",
			"user_code":                 "ABCD-1234",
			"verification_uri":          "https://auth.example.com/device",
			"verification_uri_complete": "https://auth.example.com/device?user_code=ABCD-1234",
			"expires_in":                900,
			"interval":                  5,
		})
	})

	auth, err := client.RequestDeviceCode(context.Background(), []string{"read", "write"})
	if err != nil {
		t.Fatalf("RequestDeviceCode: %v", err)
	}

	if auth.DeviceCode != "dev-code-123" {
		t.Errorf("DeviceCode = %q, want %q", auth.DeviceCode, "dev-code-123")
	}
	if auth.UserCode != "ABCD-1234" {
		t.Errorf("UserCode = %q, want %q", auth.UserCode, "ABCD-1234")
	}
	if auth.Interval != 5 {
		t.Errorf("Interval = %d, want 5", auth.Interval)
	}
	if auth.ExpiresIn != 900 {
		t.Errorf("ExpiresIn = %d, want 900", auth.ExpiresIn)
	}
}

func TestExchangeDeviceCode(t *testing.T) {
	_, client := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}

		if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
			t.Errorf("unexpected grant_type: %s", r.PostForm.Get("grant_type"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-token-123",
			"refresh_token": "refresh-token-456",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"scope":         "read write",
		})
	})

	token, err := client.ExchangeDeviceCode(context.Background(), "dev-code-123")
	if err != nil {
		t.Fatalf("ExchangeDeviceCode: %v", err)
	}

	if token.AccessToken != "access-token-123" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "access-token-123")
	}
	if token.RefreshToken != "refresh-token-456" {
		t.Errorf("RefreshToken = %q, want %q", token.RefreshToken, "refresh-token-456")
	}
	if token.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want %q", token.TokenType, "Bearer")
	}
	if token.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should not be zero")
	}
	if !token.IsValid() {
		t.Error("token should be valid")
	}
}

func TestExchangeDeviceCode_AuthorizationPending(t *testing.T) {
	_, client := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"error":             "authorization_pending",
			"error_description": "",
		})
	})

	_, err := client.ExchangeDeviceCode(context.Background(), "dev-code-123")
	if err == nil {
		t.Fatal("expected error")
	}

	var oauthErr *Error
	if !isOAuthError(err, &oauthErr) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	if oauthErr.Code != "authorization_pending" {
		t.Errorf("error code = %q, want %q", oauthErr.Code, "authorization_pending")
	}
}

func TestExchangeAuthCode(t *testing.T) {
	_, client := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if r.PostForm.Get("grant_type") != "authorization_code" {
			t.Errorf("unexpected grant_type: %s", r.PostForm.Get("grant_type"))
		}
		if r.PostForm.Get("code") != "auth-code-789" {
			t.Errorf("unexpected code: %s", r.PostForm.Get("code"))
		}
		if r.PostForm.Get("code_verifier") != "verifier-abc" {
			t.Errorf("unexpected code_verifier: %s", r.PostForm.Get("code_verifier"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-token-auth",
			"refresh_token": "refresh-token-auth",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"scope":         "openid profile",
			"id_token":      "eyJhbGciOiJIUzI1NiJ9.test.sig",
		})
	})

	token, err := client.ExchangeAuthCode(
		context.Background(),
		"auth-code-789",
		"http://localhost/callback",
		"verifier-abc",
	)
	if err != nil {
		t.Fatalf("ExchangeAuthCode: %v", err)
	}

	if token.AccessToken != "access-token-auth" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "access-token-auth")
	}
	if token.IDToken != "eyJhbGciOiJIUzI1NiJ9.test.sig" {
		t.Errorf("IDToken = %q", token.IDToken)
	}
}

func TestClientCredentials(t *testing.T) {
	_, client := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if r.PostForm.Get("grant_type") != "client_credentials" {
			t.Errorf("unexpected grant_type: %s", r.PostForm.Get("grant_type"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "cc-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "read",
		})
	})

	token, err := client.ClientCredentials(context.Background(), []string{"read"})
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}

	if token.AccessToken != "cc-access-token" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "cc-access-token")
	}
}

func TestRefreshToken(t *testing.T) {
	_, client := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if r.PostForm.Get("grant_type") != "refresh_token" {
			t.Errorf("unexpected grant_type: %s", r.PostForm.Get("grant_type"))
		}
		if r.PostForm.Get("refresh_token") != "old-refresh" {
			t.Errorf("unexpected refresh_token: %s", r.PostForm.Get("refresh_token"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-access",
			"refresh_token": "new-refresh",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	})

	token, err := client.RefreshToken(context.Background(), "old-refresh")
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}

	if token.AccessToken != "new-access" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "new-access")
	}
	if token.RefreshToken != "new-refresh" {
		t.Errorf("RefreshToken = %q, want %q", token.RefreshToken, "new-refresh")
	}
}

func TestRevoke(t *testing.T) {
	_, client := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/revoke" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	})

	err := client.Revoke(context.Background(), "some-token")
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
}

func TestIntrospect(t *testing.T) {
	_, client := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"active":     true,
			"scope":      "read write",
			"client_id":  "test-client",
			"username":   "testuser",
			"token_type": "Bearer",
			"exp":        1700000000,
			"sub":        "user-123",
		})
	})

	result, err := client.Introspect(context.Background(), "some-token")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}

	if !result.Active {
		t.Error("expected active=true")
	}
	if result.Username != "testuser" {
		t.Errorf("Username = %q, want %q", result.Username, "testuser")
	}
	if result.Sub != "user-123" {
		t.Errorf("Sub = %q, want %q", result.Sub, "user-123")
	}
}

func TestUserInfo(t *testing.T) {
	_, client := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer my-access-token" {
			t.Errorf("unexpected Authorization: %s", auth)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"sub":                "user-123",
			"name":               "Test User",
			"preferred_username": "testuser",
			"email":              "test@example.com",
		})
	})

	info, err := client.UserInfo(context.Background(), "my-access-token")
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}

	if info.Sub != "user-123" {
		t.Errorf("Sub = %q, want %q", info.Sub, "user-123")
	}
	if info.Name != "Test User" {
		t.Errorf("Name = %q, want %q", info.Name, "Test User")
	}
	if info.Email != "test@example.com" {
		t.Errorf("Email = %q, want %q", info.Email, "test@example.com")
	}
}

func TestTokenInfoRequest(t *testing.T) {
	_, client := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"active":       true,
			"user_id":      "user-123",
			"client_id":    "test-client",
			"scope":        "read write",
			"exp":          1700000000,
			"subject_type": "user",
		})
	})

	info, err := client.TokenInfoRequest(context.Background(), "my-token")
	if err != nil {
		t.Fatalf("TokenInfoRequest: %v", err)
	}

	if !info.Active {
		t.Error("expected active=true")
	}
	if info.UserID != "user-123" {
		t.Errorf("UserID = %q, want %q", info.UserID, "user-123")
	}
}

func TestTokenIsExpired(t *testing.T) {
	tok := &Token{AccessToken: "test"}
	if tok.IsExpired() {
		t.Error("token with zero ExpiresAt should not be expired")
	}

	tok.ExpiresAt = time.Now().Add(-1 * time.Hour)
	if !tok.IsExpired() {
		t.Error("token with past ExpiresAt should be expired")
	}

	tok.ExpiresAt = time.Now().Add(1 * time.Hour)
	if tok.IsExpired() {
		t.Error("token with future ExpiresAt should not be expired")
	}
}

func TestTokenIsValid(t *testing.T) {
	tok := &Token{}
	if tok.IsValid() {
		t.Error("empty token should not be valid")
	}

	tok.AccessToken = "test"
	if !tok.IsValid() {
		t.Error("token with access token and no expiry should be valid")
	}

	tok.ExpiresAt = time.Now().Add(-1 * time.Hour)
	if tok.IsValid() {
		t.Error("expired token should not be valid")
	}
}

func TestOAuthError(t *testing.T) {
	err := &Error{Code: "invalid_grant", Description: "Token expired"}
	if err.Error() != "oauth: invalid_grant: Token expired" {
		t.Errorf("unexpected error: %s", err.Error())
	}

	err2 := &Error{Code: "server_error"}
	if err2.Error() != "oauth: server_error" {
		t.Errorf("unexpected error: %s", err2.Error())
	}
}

func TestNewClient_WithOptions(t *testing.T) {
	ep := Endpoints{TokenURL: "https://example.com/token"}
	client, err := NewClient("my-client", ep, WithClientSecret("my-secret"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if client.ClientID() != "my-client" {
		t.Errorf("ClientID = %q, want %q", client.ClientID(), "my-client")
	}
	if client.clientSecret != "my-secret" {
		t.Errorf("clientSecret = %q, want %q", client.clientSecret, "my-secret")
	}
}

func TestRequestDeviceCode_NoEndpoint(t *testing.T) {
	client, err := NewClient("test", Endpoints{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.RequestDeviceCode(context.Background(), []string{"read"})
	if err == nil {
		t.Fatal("expected error for missing endpoint")
	}
}

func isOAuthError(err error, target **Error) bool {
	var oauthErr *Error
	for e := err; e != nil; {
		if oe, is := e.(*Error); is {
			*target = oe
			return true
		}
		if u, is := e.(interface{ Unwrap() error }); is {
			e = u.Unwrap()
		} else {
			break
		}
	}
	_ = oauthErr
	return false
}
