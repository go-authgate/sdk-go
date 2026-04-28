package jwksauth

import (
	"fmt"
	"net/http"
	"strings"
)

// RFC 6750 error codes accepted by [WriteAuthError].
const (
	// ErrCodeInvalidRequest matches RFC 6750 §3.1 invalid_request. The
	// Bearer credential was supplied in some form but the request is
	// malformed (e.g. "Bearer" with no token, or extra tokens after the
	// bearer value). Triggers a 400 response.
	ErrCodeInvalidRequest = "invalid_request"

	// ErrCodeInvalidToken matches RFC 6750 §3.1 invalid_token. The token
	// itself is invalid — bad signature, expired, wrong issuer/audience,
	// or rejected by AccessRule. Triggers a 401 response.
	ErrCodeInvalidToken = "invalid_token"

	// ErrCodeInsufficientScope matches RFC 6750 §3.1 insufficient_scope.
	// Triggers a 403 response and may include the required scopes in the
	// WWW-Authenticate challenge.
	ErrCodeInsufficientScope = "insufficient_scope"
)

// WriteAuthError writes an RFC 6750 §3.1 compliant Bearer challenge for the
// "credentials were supplied but rejected" cases:
//
//   - 401 invalid_token — the token failed verification or policy.
//   - 403 insufficient_scope — the token is valid but lacks a required scope.
//
// When scopes are supplied they are advertised via the `scope` attribute
// per §3.1, letting the client know what to request next time. Any quotes
// in code/desc are escaped using %q so the header stays parseable.
//
// For the fully missing-credentials case (no Authorization header at all),
// RFC 6750 §3 says the challenge MUST NOT include an `error` attribute —
// emit a bare `WWW-Authenticate: Bearer` instead of using this helper.
func WriteAuthError(w http.ResponseWriter, code, desc string, scopes ...string) {
	status := http.StatusUnauthorized
	switch code {
	case ErrCodeInsufficientScope:
		status = http.StatusForbidden
	case ErrCodeInvalidRequest:
		status = http.StatusBadRequest
	}
	challenge := fmt.Sprintf(`Bearer error=%q, error_description=%q`, code, desc)
	if len(scopes) > 0 {
		challenge += fmt.Sprintf(`, scope=%q`, strings.Join(scopes, " "))
	}
	w.Header().Set("WWW-Authenticate", challenge)
	http.Error(w, desc, status)
}
