package jwksauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ErrMalformedJWT indicates the Authorization header value is not a JWT.
// Returned by [UnverifiedIssuer] and from the multi-issuer routing path;
// check with errors.Is.
var ErrMalformedJWT = errors.New("malformed JWT")

// UnverifiedIssuer extracts the `iss` claim from a JWT payload WITHOUT
// validating the signature. The returned value MUST only be used to choose
// which verifier to dispatch to; it must never drive trust decisions on its
// own. The chosen verifier subsequently re-checks `iss` together with the
// signature.
//
// The parser caps the input at four dot-separated segments to prevent a
// pathological Authorization header (packed with dots) from triggering
// large allocations on the base64-decode path before signature verification
// has a chance to reject it.
func UnverifiedIssuer(raw string) (string, error) {
	// Cap=4 so a 4+ segment token fails the len==3 check below before any
	// base64 work happens.
	parts := strings.SplitN(raw, ".", 4)
	if len(parts) != 3 {
		return "", ErrMalformedJWT
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode JWT payload: %w", err)
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", fmt.Errorf("parse JWT payload: %w", err)
	}
	if c.Iss == "" {
		return "", errors.New("JWT missing iss claim")
	}
	return c.Iss, nil
}
