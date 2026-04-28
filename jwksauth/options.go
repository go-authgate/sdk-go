package jwksauth

import "time"

// Option configures [Verifier] and [MultiVerifier] construction.
type Option interface {
	apply(*verifierConfig)
}

// verifierConfig holds the resolved options shared by both verifier
// constructors. It is unexported on purpose; callers configure it via the
// Option helpers.
type verifierConfig struct {
	verifyTimeout    time.Duration
	discoveryTimeout time.Duration
}

func defaultVerifierConfig() verifierConfig {
	return verifierConfig{
		verifyTimeout:    5 * time.Second,
		discoveryTimeout: 15 * time.Second,
	}
}

type optionFunc func(*verifierConfig)

func (f optionFunc) apply(c *verifierConfig) { f(c) }

// WithVerifyTimeout sets the per-request verification timeout. Defaults to
// 5 seconds. The timeout bounds the JWKS-refresh round-trip that go-oidc
// performs when it sees a previously-unknown key id; pure signature checks
// are sub-millisecond and won't come close to it.
func WithVerifyTimeout(d time.Duration) Option {
	return optionFunc(func(c *verifierConfig) {
		if d > 0 {
			c.verifyTimeout = d
		}
	})
}

// WithDiscoveryTimeout sets the upper bound on OIDC discovery during
// construction. Defaults to 15 seconds. For [NewMultiVerifier] this is the
// total budget across all issuers (they discover concurrently), so one slow
// issuer cannot multiply startup time by N.
func WithDiscoveryTimeout(d time.Duration) Option {
	return optionFunc(func(c *verifierConfig) {
		if d > 0 {
			c.discoveryTimeout = d
		}
	})
}
