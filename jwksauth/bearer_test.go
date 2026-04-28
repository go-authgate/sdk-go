package jwksauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name string
		hdr  string
		want string
	}{
		{"empty", "", ""},
		{"plain bearer", "Bearer abc.def.ghi", "abc.def.ghi"},
		{"lower-case scheme", "bearer abc.def.ghi", "abc.def.ghi"},
		{"upper-case scheme", "BEARER abc.def.ghi", "abc.def.ghi"},
		{"extra spaces", "Bearer    abc.def.ghi", "abc.def.ghi"},
		{"tab-separated", "Bearer\tabc.def.ghi", "abc.def.ghi"},
		{"missing token", "Bearer", ""},
		{"wrong scheme", "Basic dXNlcjpwYXNz", ""},
		{"three parts", "Bearer abc more", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.hdr != "" {
				req.Header.Set("Authorization", tc.hdr)
			}
			if got := ExtractBearerToken(req); got != tc.want {
				t.Errorf("ExtractBearerToken() = %q, want %q", got, tc.want)
			}
		})
	}
}
