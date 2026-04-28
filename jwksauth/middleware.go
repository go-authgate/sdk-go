package jwksauth

import (
	"context"
	"log"
	"net/http"
)

// TokenVerifier is the contract [Middleware] uses to validate tokens. Both
// [Verifier] (single issuer) and [MultiVerifier] satisfy it; tests and
// custom integrations can supply alternate implementations.
type TokenVerifier interface {
	Verify(ctx context.Context, raw string) (*TokenInfo, error)
}

// Logger is the minimal logging surface [Middleware] needs. The standard
// library's *log.Logger satisfies it; pass any structured logger by
// adapting Printf.
type Logger interface {
	Printf(format string, args ...any)
}

// MiddlewareOption configures [Middleware].
type MiddlewareOption interface {
	apply(*middlewareConfig)
}

type middlewareConfig struct {
	logger Logger
}

type middlewareOptionFunc func(*middlewareConfig)

func (f middlewareOptionFunc) apply(c *middlewareConfig) { f(c) }

// WithLogger sets the logger used for server-side reporting of verification
// failures. Defaults to the standard library's [log.Default]. Failures are
// always logged with full detail server-side; clients receive the generic
// RFC 6750 challenge so verifier internals (expected issuer, audience,
// allowlist contents) do not leak.
func WithLogger(l Logger) MiddlewareOption {
	return middlewareOptionFunc(func(c *middlewareConfig) {
		if l != nil {
			c.logger = l
		}
	})
}

// Middleware returns an HTTP middleware that verifies the Authorization
// Bearer token and enforces rule before delegating to next.
//
// Behavior on each request:
//   - No Authorization header: 401 with bare `WWW-Authenticate: Bearer`
//     (RFC 6750 §3 — error attribute is reserved for cases where credentials
//     were supplied but rejected).
//   - Token verification fails: 401 invalid_token. Full error logged
//     server-side; client gets a generic description.
//   - Required scope missing: 403 insufficient_scope, advertising the
//     missing scope so the client can request it next time.
//   - Custom-claim allowlist mismatch: 401 invalid_token. Reason is logged
//     server-side; client sees a generic message so the allowlist itself
//     is not probeable.
//   - All checks pass: [TokenInfo] is attached to the request context; use
//     [TokenInfoFromContext] in your handler to read it.
//
// rule is canonicalized once on construction (Tenants lower-cased, slices
// cloned), so callers may safely mutate their input afterwards.
func Middleware(
	v TokenVerifier,
	rule AccessRule,
	opts ...MiddlewareOption,
) func(http.Handler) http.Handler {
	cfg := middlewareConfig{logger: log.Default()}
	for _, o := range opts {
		if o != nil {
			o.apply(&cfg)
		}
	}
	rule = rule.canonical()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := ExtractBearerToken(r)
			if raw == "" {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			info, err := v.Verify(r.Context(), raw)
			if err != nil {
				cfg.logger.Printf("jwksauth: token verification failed: %v", err)
				WriteAuthError(w, ErrCodeInvalidToken, "invalid token")
				return
			}
			for _, scope := range rule.Scopes {
				if !info.HasScope(scope) {
					WriteAuthError(
						w,
						ErrCodeInsufficientScope,
						"required scope: "+scope,
						scope,
					)
					return
				}
			}
			if reason, ok := rule.checkClaims(info); !ok {
				cfg.logger.Printf(
					"jwksauth: policy reject: %s (sub=%q iss=%q)",
					reason, info.Subject, info.Issuer,
				)
				WriteAuthError(
					w,
					ErrCodeInvalidToken,
					"token not authorized for this resource",
				)
				return
			}
			next.ServeHTTP(w, r.WithContext(withTokenInfo(r.Context(), info)))
		})
	}
}

// Compile-time assertion that the bundled verifiers satisfy [TokenVerifier].
// Any change that breaks this also breaks Middleware compilation.
var (
	_ TokenVerifier = (*Verifier)(nil)
	_ TokenVerifier = (*MultiVerifier)(nil)
)
