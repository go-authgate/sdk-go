package jwksauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ErrMalformedJWT indicates the Authorization header value cannot be parsed
// as a JWT — wrong number of segments, undecodable base64 payload, invalid
// JSON, or missing `iss` claim. Every error path in [UnverifiedIssuer]
// wraps this sentinel so callers can detect "not a JWT" with a single
// errors.Is check.
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
//
// All errors wrap [ErrMalformedJWT].
func UnverifiedIssuer(raw string) (string, error) {
	// Cap=4 so a 4+ segment token fails the len==3 check below before any
	// base64 work happens.
	parts := strings.SplitN(raw, ".", 4)
	if len(parts) != 3 {
		return "", ErrMalformedJWT
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("%w: decode payload: %w", ErrMalformedJWT, err)
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", fmt.Errorf("%w: parse payload: %w", ErrMalformedJWT, err)
	}
	if c.Iss == "" {
		return "", fmt.Errorf("%w: missing iss claim", ErrMalformedJWT)
	}
	return c.Iss, nil
}
