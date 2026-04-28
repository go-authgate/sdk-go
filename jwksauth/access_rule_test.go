package jwksauth

import "testing"

func newInfo(tenant, sa, project string) *TokenInfo {
	return &TokenInfo{
		Claims: Claims{
			Tenant:         tenant,
			ServiceAccount: sa,
			Project:        project,
		},
		tenant: lower(tenant),
	}
}

// lower is the same case-fold the verifier applies; duplicated here so the
// test does not reach into the verifier construction path.
func lower(s string) string {
	out := make([]byte, len(s))
	for i := range len(s) {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

func TestAccessRule_EmptyAllowsAll(t *testing.T) {
	rule := AccessRule{}.canonical()
	if reason, ok := rule.checkClaims(newInfo("", "", "")); !ok {
		t.Errorf("empty rule should accept; reason=%q", reason)
	}
}

func TestAccessRule_TenantAllowlistCaseInsensitive(t *testing.T) {
	rule := AccessRule{Tenants: []string{"OA", "HwRd"}}.canonical()

	if _, ok := rule.checkClaims(newInfo("oa", "", "")); !ok {
		t.Error("tenant=oa should match (input was OA)")
	}
	if _, ok := rule.checkClaims(newInfo("HWRD", "", "")); !ok {
		t.Error("tenant=HWRD should match (input was HwRd)")
	}
	if _, ok := rule.checkClaims(newInfo("swrd", "", "")); ok {
		t.Error("tenant=swrd should not match")
	}
}

func TestAccessRule_FailClosedOnMissingClaim(t *testing.T) {
	rule := AccessRule{Tenants: []string{"oa"}}.canonical()
	if _, ok := rule.checkClaims(newInfo("", "", "")); ok {
		t.Error("missing tenant should be rejected when allowlist is set")
	}
}

func TestAccessRule_ServiceAccountExactMatch(t *testing.T) {
	rule := AccessRule{ServiceAccounts: []string{"sync-bot@oa.local"}}.canonical()
	if _, ok := rule.checkClaims(newInfo("", "sync-bot@oa.local", "")); !ok {
		t.Error("exact match should accept")
	}
	if _, ok := rule.checkClaims(newInfo("", "SYNC-BOT@OA.LOCAL", "")); ok {
		t.Error("ServiceAccounts must be case-sensitive")
	}
}

func TestAccessRule_ProjectAllowlist(t *testing.T) {
	rule := AccessRule{Projects: []string{"admin-tools"}}.canonical()
	if _, ok := rule.checkClaims(newInfo("", "", "admin-tools")); !ok {
		t.Error("project should match")
	}
	if _, ok := rule.checkClaims(newInfo("", "", "other")); ok {
		t.Error("project should not match")
	}
}

func TestAccessRule_CanonicalIsCopy(t *testing.T) {
	original := AccessRule{Scopes: []string{"email"}, Tenants: []string{"OA"}}
	canon := original.canonical()
	original.Scopes[0] = "mutated"
	original.Tenants[0] = "MUTATED"
	if canon.Scopes[0] != "email" {
		t.Error("canonical().Scopes should not alias caller's slice")
	}
	if canon.Tenants[0] != "oa" {
		t.Error("canonical().Tenants should be lower-cased copy")
	}
}
