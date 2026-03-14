package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestServer(t *testing.T, meta Metadata) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wellKnownPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestFetch(t *testing.T) {
	meta := Metadata{
		Issuer:                "https://auth.example.com",
		AuthorizationEndpoint: "https://auth.example.com/oauth/authorize",
		TokenEndpoint:         "https://auth.example.com/oauth/token",
		UserinfoEndpoint:      "https://auth.example.com/oauth/userinfo",
		RevocationEndpoint:    "https://auth.example.com/oauth/revoke",
		GrantTypesSupported: []string{
			"authorization_code",
			"urn:ietf:params:oauth:grant-type:device_code",
			"refresh_token",
			"client_credentials",
		},
		ScopesSupported: []string{"openid", "profile", "email"},
	}

	server := newTestServer(t, meta)

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result, err := client.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if result.Issuer != meta.Issuer {
		t.Errorf("Issuer = %q, want %q", result.Issuer, meta.Issuer)
	}
	if result.TokenEndpoint != meta.TokenEndpoint {
		t.Errorf("TokenEndpoint = %q, want %q", result.TokenEndpoint, meta.TokenEndpoint)
	}
	if result.DeviceAuthorizationEndpoint == "" {
		t.Error("DeviceAuthorizationEndpoint should be derived from issuer")
	}
	if result.IntrospectionEndpoint == "" {
		t.Error("IntrospectionEndpoint should be derived from issuer")
	}
}

func TestFetch_Cache(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Metadata{
			Issuer:        "https://auth.example.com",
			TokenEndpoint: "https://auth.example.com/oauth/token",
		})
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL, WithCacheTTL(1*time.Hour))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch 1: %v", err)
	}

	_, err = client.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch 2: %v", err)
	}

	if callCount != 1 {
		t.Errorf("server called %d times, want 1 (cached)", callCount)
	}
}

func TestEndpoints(t *testing.T) {
	meta := &Metadata{
		Issuer:                      "https://auth.example.com",
		AuthorizationEndpoint:       "https://auth.example.com/oauth/authorize",
		TokenEndpoint:               "https://auth.example.com/oauth/token",
		UserinfoEndpoint:            "https://auth.example.com/oauth/userinfo",
		RevocationEndpoint:          "https://auth.example.com/oauth/revoke",
		IntrospectionEndpoint:       "https://auth.example.com/oauth/introspect",
		DeviceAuthorizationEndpoint: "https://auth.example.com/oauth/device/code",
	}

	ep := meta.Endpoints()

	if ep.TokenURL != meta.TokenEndpoint {
		t.Errorf("TokenURL = %q, want %q", ep.TokenURL, meta.TokenEndpoint)
	}
	if ep.AuthorizeURL != meta.AuthorizationEndpoint {
		t.Errorf("AuthorizeURL = %q, want %q", ep.AuthorizeURL, meta.AuthorizationEndpoint)
	}
	if ep.DeviceAuthorizationURL != meta.DeviceAuthorizationEndpoint {
		t.Errorf(
			"DeviceAuthorizationURL = %q, want %q",
			ep.DeviceAuthorizationURL,
			meta.DeviceAuthorizationEndpoint,
		)
	}
	if ep.TokenInfoURL != "https://auth.example.com/oauth/tokeninfo" {
		t.Errorf("TokenInfoURL = %q", ep.TokenInfoURL)
	}
}

func TestFetch_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL, WithCacheTTL(0))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}
