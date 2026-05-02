package jwksauth

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var errEmptyPrivateClaimPrefix = errors.New("must not be empty")

// defaultPrivateClaimPrefix matches upstream AuthGate's JWT_PRIVATE_CLAIM_PREFIX
// default. Server and SDK must agree byte-for-byte; if a deployment has
// overridden this on the server, configure the SDK with [WithPrivateClaimPrefix].
const defaultPrivateClaimPrefix = "extra"

// maxPrivateClaimPrefixLen mirrors upstream's length cap on the prefix.
const maxPrivateClaimPrefixLen = 15

// privateClaimPrefixPattern mirrors upstream validateJWTPrivateClaimPrefix:
// must start with a letter; subsequent characters are letters, digits, or
// underscore. The "must not end with underscore" rule is enforced
// separately so the error message can name that specific violation.
var privateClaimPrefixPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*$`)

// Option configures [Verifier] and [MultiVerifier] construction.
type Option interface {
	apply(*verifierConfig)
}

// verifierConfig holds the resolved options shared by both verifier
// constructors. It is unexported on purpose; callers configure it via the
// Option helpers.
type verifierConfig struct {
	verifyTimeout      time.Duration
	discoveryTimeout   time.Duration
	privateClaimPrefix string
}

func defaultVerifierConfig() verifierConfig {
	return verifierConfig{
		verifyTimeout:      5 * time.Second,
		discoveryTimeout:   15 * time.Second,
		privateClaimPrefix: defaultPrivateClaimPrefix,
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

// WithPrivateClaimPrefix configures the prefix the SDK uses when reading
// AuthGate's server-attested private claims (Domain, Project,
// ServiceAccount). Defaults to "extra"; pass the value here only when
// the AuthGate deployment has overridden JWT_PRIVATE_CLAIM_PREFIX. Server
// and SDK must agree byte-for-byte — reading with the wrong prefix
// yields empty fields and (when AccessRule covers those dimensions)
// fails closed.
//
// Surrounding whitespace is trimmed; an empty or whitespace-only string is
// treated as "use the default" (consistent with [WithVerifyTimeout]'s
// zero-input handling). Format errors are returned from [NewVerifier] /
// [NewMultiVerifier], never silently ignored.
func WithPrivateClaimPrefix(p string) Option {
	return optionFunc(func(c *verifierConfig) {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			c.privateClaimPrefix = trimmed
		}
	})
}

// validatePrivateClaimPrefix mirrors upstream validateJWTPrivateClaimPrefix.
// Rules: 1-15 characters, starts with a letter, only letters/digits/underscore,
// must not end with an underscore (which would yield "<prefix>__<logical>"
// after the EmittedName join).
//
// Reserved-key collision checks are intentionally left to the server side;
// duplicating them in the SDK adds maintenance with no defense gain.
func validatePrivateClaimPrefix(p string) error {
	if p == "" {
		return errEmptyPrivateClaimPrefix
	}
	if len(p) > maxPrivateClaimPrefixLen {
		return fmt.Errorf("%q exceeds %d characters", p, maxPrivateClaimPrefixLen)
	}
	if !privateClaimPrefixPattern.MatchString(p) {
		return fmt.Errorf(
			"%q must match %s",
			p,
			privateClaimPrefixPattern.String(),
		)
	}
	if p[len(p)-1] == '_' {
		return fmt.Errorf("%q must not end with underscore", p)
	}
	return nil
}
