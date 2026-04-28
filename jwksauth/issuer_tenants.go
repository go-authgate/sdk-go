package jwksauth

import (
	"fmt"
	"slices"
	"strings"
)

// ParseIssuerTenants parses the cross-tenant pinning configuration. The
// encoding is:
//
//	iss1=tenantA,tenantB;iss2=tenantC,tenantD
//
// known is the set of canonical issuers permitted as left-hand sides; pass
// [MultiVerifier.Issuers]() so a typo in the variable is caught at startup.
//
// Rules enforced:
//   - Every entry's left-hand side must appear in known.
//   - Every issuer in known must appear exactly once in raw — a silent gap
//     would let one issuer mint tokens for any tenant.
//   - A tenant must be owned by exactly one issuer.
//   - Same-issuer duplicates ("oa,oa") are reported as typos so the error
//     points at the actual mistake rather than a confusing cross-issuer
//     overlap message.
//
// Tenant codes are lower-cased so [AccessRule] and the cross-tenant
// allowlist enforcement can compare tenants case-insensitively.
//
// Returns nil with no error when raw is empty — the caller can treat that
// as "cross-tenant enforcement disabled".
func ParseIssuerTenants(raw string, known []string) (map[string][]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		// nil map is the documented signal for "enforcement disabled" —
		// callers that want strict checking can pass a non-empty raw.
		return nil, nil //nolint:nilnil // intentional: nil map = enforcement disabled
	}
	knownSet := make(map[string]struct{}, len(known))
	for _, k := range known {
		knownSet[k] = struct{}{}
	}

	out := make(map[string][]string)
	for entry := range strings.SplitSeq(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		iss, tenantsRaw, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf(
				"malformed ISSUER_TENANTS entry %q (want iss=tenantA,tenantB)",
				entry,
			)
		}
		iss = strings.TrimSpace(iss)
		if _, found := knownSet[iss]; !found {
			canonical := slices.Clone(known)
			slices.Sort(canonical)
			return nil, fmt.Errorf(
				"ISSUER_TENANTS issuer %q is not a registered issuer (known: %v)",
				iss, canonical,
			)
		}

		var tenants []string
		for t := range strings.SplitSeq(tenantsRaw, ",") {
			t = strings.ToLower(strings.TrimSpace(t))
			if t != "" {
				tenants = append(tenants, t)
			}
		}
		if len(tenants) == 0 {
			return nil, fmt.Errorf("issuer %q in ISSUER_TENANTS has no tenants", iss)
		}
		if _, dup := out[iss]; dup {
			return nil, fmt.Errorf("duplicate issuer in ISSUER_TENANTS: %s", iss)
		}
		out[iss] = tenants
	}

	for _, iss := range known {
		if _, ok := out[iss]; !ok {
			return nil, fmt.Errorf(
				"issuer %q is missing from ISSUER_TENANTS (every registered issuer must be listed when ISSUER_TENANTS is set)",
				iss,
			)
		}
	}

	// A tenant must be owned by exactly ONE issuer; otherwise the cross-
	// tenant defense degrades silently. Distinguish "same tenant listed
	// twice for the same issuer" (typo, e.g. "oa,oa") from a true cross-
	// issuer overlap so the error message points at the actual mistake.
	tenantOwner := make(map[string]string, len(out))
	for iss, tenants := range out {
		for _, t := range tenants {
			if other, dup := tenantOwner[t]; dup {
				if other == iss {
					return nil, fmt.Errorf(
						"tenant %q listed twice for issuer %q in ISSUER_TENANTS — drop the duplicate",
						t,
						iss,
					)
				}
				return nil, fmt.Errorf(
					"tenant %q listed under multiple issuers in ISSUER_TENANTS (%q and %q) — a tenant must be owned by exactly one issuer",
					t,
					other,
					iss,
				)
			}
			tenantOwner[t] = iss
		}
	}
	return out, nil
}
