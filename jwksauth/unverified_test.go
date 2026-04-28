package jwksauth

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// makeJWT assembles a syntactically-valid JWT (no signature math) with the
// given payload JSON. It is enough for testing UnverifiedIssuer; we never
// validate the signature here.
func makeJWT(t *testing.T, payloadJSON string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	return header + "." + payload + ".sig"
}

func TestUnverifiedIssuer_Happy(t *testing.T) {
	tok := makeJWT(t, `{"iss":"https://auth.example.com","sub":"u1"}`)
	got, err := UnverifiedIssuer(tok)
	if err != nil {
		t.Fatalf("UnverifiedIssuer: %v", err)
	}
	if got != "https://auth.example.com" {
		t.Errorf("iss = %q, want https://auth.example.com", got)
	}
}

func TestUnverifiedIssuer_Errors(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"one segment", "abc"},
		{"two segments", "abc.def"},
		{"too many segments", "a.b.c.d.e.f"},
		{"bad base64 payload", "abc.@@@.ghi"},
		{
			"non-json payload",
			"abc." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".ghi",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := UnverifiedIssuer(tc.raw)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestUnverifiedIssuer_MalformedSentinel(t *testing.T) {
	_, err := UnverifiedIssuer("only-one-segment")
	if !errors.Is(err, ErrMalformedJWT) {
		t.Errorf("error = %v, want ErrMalformedJWT", err)
	}
}

func TestUnverifiedIssuer_MissingIss(t *testing.T) {
	tok := makeJWT(t, `{"sub":"u1"}`)
	_, err := UnverifiedIssuer(tok)
	if err == nil || !strings.Contains(err.Error(), "iss") {
		t.Fatalf("expected missing-iss error, got %v", err)
	}
}

// TestUnverifiedIssuer_ManyDots ensures the SplitN cap prevents pathological
// inputs from succeeding. A JWT with extra dots inside its payload segment
// is still 3-part if encoded properly; the test below uses 4+ parts to
// exercise the early reject.
func TestUnverifiedIssuer_ManyDots(t *testing.T) {
	raw := strings.Repeat("a.", 100) + "b"
	_, err := UnverifiedIssuer(raw)
	if err == nil {
		t.Fatal("expected error for many-dot input")
	}
}
