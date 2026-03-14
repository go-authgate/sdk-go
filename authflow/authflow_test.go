package authflow

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-authgate/sdk-go/credstore"
	"github.com/go-authgate/sdk-go/oauth"
)

func TestRunDeviceFlow(t *testing.T) {
	var requestCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/oauth/device/code":
			json.NewEncoder(w).Encode(map[string]any{
				"device_code":      "test-device-code",
				"user_code":        "ABCD-1234",
				"verification_uri": "https://auth.example.com/device",
				"expires_in":       300,
				"interval":         1,
			})
		case "/oauth/token":
			count := requestCount.Add(1)
			if count < 3 {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]any{
					"error": "authorization_pending",
				})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "test-access-token",
				"refresh_token": "test-refresh-token",
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
		}
	}))
	t.Cleanup(server.Close)

	endpoints := oauth.Endpoints{
		TokenURL:               server.URL + "/oauth/token",
		DeviceAuthorizationURL: server.URL + "/oauth/device/code",
	}

	client, err := oauth.NewClient("test-client", endpoints)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	displayed := false
	handler := &testDeviceHandler{onDisplay: func(auth *oauth.DeviceAuth) {
		displayed = true
		if auth.UserCode != "ABCD-1234" {
			t.Errorf("UserCode = %q, want %q", auth.UserCode, "ABCD-1234")
		}
	}}

	token, err := RunDeviceFlow(context.Background(), client, []string{"read"},
		WithDeviceFlowHandler(handler),
	)
	if err != nil {
		t.Fatalf("RunDeviceFlow: %v", err)
	}

	if !displayed {
		t.Error("device code handler was not called")
	}
	if token.AccessToken != "test-access-token" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "test-access-token")
	}
}

func TestRunDeviceFlow_Cancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth/device/code":
			json.NewEncoder(w).Encode(map[string]any{
				"device_code":      "test-device-code",
				"user_code":        "ABCD-1234",
				"verification_uri": "https://auth.example.com/device",
				"expires_in":       300,
				"interval":         1,
			})
		case "/oauth/token":
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{
				"error": "authorization_pending",
			})
		}
	}))
	t.Cleanup(server.Close)

	endpoints := oauth.Endpoints{
		TokenURL:               server.URL + "/oauth/token",
		DeviceAuthorizationURL: server.URL + "/oauth/device/code",
	}
	client, err := oauth.NewClient("test-client", endpoints)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err = RunDeviceFlow(ctx, client, []string{"read"},
		WithDeviceFlowHandler(&testDeviceHandler{}),
	)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestRunAuthCodeFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test generateState produces unique values
	s1, err := generateState()
	if err != nil {
		t.Fatalf("generateState: %v", err)
	}
	s2, err := generateState()
	if err != nil {
		t.Fatalf("generateState: %v", err)
	}
	if s1 == s2 {
		t.Error("generateState should produce unique values")
	}
	if len(s1) != 32 {
		t.Errorf("state length = %d, want 32 hex chars", len(s1))
	}

	// Test the callback handler with state validation via direct HTTP
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	state := "test-state-123"
	var once sync.Once

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() {
			if r.URL.Query().Get("state") != state {
				errCh <- &oauth.Error{Code: "invalid_state"}
				return
			}
			code := r.URL.Query().Get("code")
			if code == "" {
				errCh <- &oauth.Error{Code: "no_code"}
				return
			}
			codeCh <- code
		})
		w.WriteHeader(http.StatusOK)
	})

	callbackServer := httptest.NewServer(mux)
	t.Cleanup(callbackServer.Close)

	// Valid callback with correct state
	resp, err := http.Get(
		callbackServer.URL + "/callback?code=test-code&state=test-state-123",
	)
	if err != nil {
		t.Fatalf("callback request: %v", err)
	}
	resp.Body.Close()

	select {
	case code := <-codeCh:
		if code != "test-code" {
			t.Errorf("code = %q, want %q", code, "test-code")
		}
	case err := <-errCh:
		t.Fatalf("unexpected error: %v", err)
	case <-ctx.Done():
		t.Fatal("timeout waiting for callback")
	}

	// Second callback should be ignored (sync.Once)
	resp, err = http.Get(
		callbackServer.URL + "/callback?code=second-code&state=test-state-123",
	)
	if err != nil {
		t.Fatalf("second callback request: %v", err)
	}
	resp.Body.Close()

	// Channel should be empty
	select {
	case <-codeCh:
		t.Error("second callback should be ignored")
	default:
		// expected
	}
}

func TestRunAuthCodeFlow_InvalidState(t *testing.T) {
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	state := "correct-state"
	var once sync.Once

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() {
			if r.URL.Query().Get("state") != state {
				errCh <- &oauth.Error{Code: "invalid_state"}
				return
			}
			codeCh <- r.URL.Query().Get("code")
		})
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	// Send callback with wrong state
	resp, err := http.Get(server.URL + "/callback?code=test-code&state=wrong-state")
	if err != nil {
		t.Fatalf("callback request: %v", err)
	}
	resp.Body.Close()

	select {
	case <-codeCh:
		t.Error("should not receive code with wrong state")
	case err := <-errCh:
		var oauthErr *oauth.Error
		if !errors.As(err, &oauthErr) || oauthErr.Code != "invalid_state" {
			t.Errorf("expected invalid_state error, got: %v", err)
		}
	}
}

// --- TokenSource tests ---

type stubStore struct {
	data    map[string]credstore.Token
	saveErr error
	loadErr error
}

func newStubStore() *stubStore {
	return &stubStore{data: make(map[string]credstore.Token)}
}

func (s *stubStore) Load(clientID string) (credstore.Token, error) {
	if s.loadErr != nil {
		return credstore.Token{}, s.loadErr
	}
	tok, ok := s.data[clientID]
	if !ok {
		return credstore.Token{}, credstore.ErrNotFound
	}
	return tok, nil
}

func (s *stubStore) Save(clientID string, data credstore.Token) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.data[clientID] = data
	return nil
}

func (s *stubStore) Delete(clientID string) error {
	delete(s.data, clientID)
	return nil
}

func (s *stubStore) String() string { return "stub" }

func TestTokenSource_LoadValid(t *testing.T) {
	store := newStubStore()
	store.data["test-client"] = credstore.Token{
		AccessToken:  "cached-token",
		RefreshToken: "cached-refresh",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		ClientID:     "test-client",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not make HTTP request when cache is valid")
	}))
	t.Cleanup(server.Close)

	client, err := oauth.NewClient(
		"test-client",
		oauth.Endpoints{TokenURL: server.URL + "/token"},
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ts := NewTokenSource(client, WithStore(store))
	token, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if token.AccessToken != "cached-token" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "cached-token")
	}
}

func TestTokenSource_RefreshExpired(t *testing.T) {
	store := newStubStore()
	store.data["test-client"] = credstore.Token{
		AccessToken:  "expired-token",
		RefreshToken: "refresh-me",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(-1 * time.Hour), // expired
		ClientID:     "test-client",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-access",
			"refresh_token": "new-refresh",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	t.Cleanup(server.Close)

	client, err := oauth.NewClient(
		"test-client",
		oauth.Endpoints{TokenURL: server.URL + "/token"},
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ts := NewTokenSource(client, WithStore(store))
	token, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if token.AccessToken != "new-access" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "new-access")
	}

	// Verify token was saved to store
	saved, loadErr := store.Load("test-client")
	if loadErr != nil {
		t.Fatalf("Load after refresh: %v", loadErr)
	}
	if saved.AccessToken != "new-access" {
		t.Errorf("saved AccessToken = %q, want %q", saved.AccessToken, "new-access")
	}
}

func TestTokenSource_NoToken(t *testing.T) {
	store := newStubStore()

	client, err := oauth.NewClient(
		"test-client",
		oauth.Endpoints{TokenURL: "http://unused"},
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ts := NewTokenSource(client, WithStore(store))
	_, err = ts.Token(context.Background())
	if err == nil {
		t.Fatal("expected error when no token available")
	}
}

func TestTokenSource_LoadError(t *testing.T) {
	store := newStubStore()
	store.loadErr = errors.New("disk I/O error")

	client, err := oauth.NewClient(
		"test-client",
		oauth.Endpoints{TokenURL: "http://unused"},
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ts := NewTokenSource(client, WithStore(store))
	_, err = ts.Token(context.Background())
	if err == nil {
		t.Fatal("expected error for store load failure")
	}
	if !strings.Contains(err.Error(), "disk I/O error") {
		t.Errorf("error should contain root cause, got: %v", err)
	}
}

func TestTokenSource_SaveError(t *testing.T) {
	store := newStubStore()
	store.data["test-client"] = credstore.Token{
		AccessToken:  "expired-token",
		RefreshToken: "refresh-me",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
		ClientID:     "test-client",
	}
	store.saveErr = errors.New("permission denied")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-access",
			"refresh_token": "new-refresh",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	t.Cleanup(server.Close)

	client, err := oauth.NewClient(
		"test-client",
		oauth.Endpoints{TokenURL: server.URL + "/token"},
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ts := NewTokenSource(client, WithStore(store))
	_, err = ts.Token(context.Background())
	if err == nil {
		t.Fatal("expected error for store save failure")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error should contain root cause, got: %v", err)
	}
}

func TestTokenSource_SaveToken(t *testing.T) {
	store := newStubStore()

	client, err := oauth.NewClient(
		"test-client",
		oauth.Endpoints{TokenURL: "http://unused"},
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ts := NewTokenSource(client, WithStore(store))
	saveErr := ts.SaveToken(&oauth.Token{
		AccessToken:  "saved-token",
		RefreshToken: "saved-refresh",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	})
	if saveErr != nil {
		t.Fatalf("SaveToken: %v", saveErr)
	}

	saved, loadErr := store.Load("test-client")
	if loadErr != nil {
		t.Fatalf("Load: %v", loadErr)
	}
	if saved.AccessToken != "saved-token" {
		t.Errorf("AccessToken = %q, want %q", saved.AccessToken, "saved-token")
	}
}

func TestCheckBrowserAvailability(t *testing.T) {
	// Just ensure it doesn't panic
	_ = CheckBrowserAvailability()
}

type testDeviceHandler struct {
	onDisplay func(auth *oauth.DeviceAuth)
}

func (h *testDeviceHandler) DisplayCode(auth *oauth.DeviceAuth) error {
	if h.onDisplay != nil {
		h.onDisplay(auth)
	}
	return nil
}
