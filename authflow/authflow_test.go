package authflow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

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
