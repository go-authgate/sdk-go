package jwksauth

import (
	"net/http"
	"strings"
)

// ExtractBearerToken returns the token from the Authorization header, or
// the empty string if the header is missing or malformed.
//
// The parser splits on any whitespace so it tolerates odd Authorization
// headers in the wild (extra spaces, tabs) while still enforcing the
// two-part scheme + token shape and case-insensitive "Bearer" per
// RFC 6750 §2.1.
func ExtractBearerToken(r *http.Request) string {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}
