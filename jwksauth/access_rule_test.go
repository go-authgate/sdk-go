package jwksauth

import "testing"

func newInfo(tenant, sa, project string) *TokenInfo {
	return &TokenInfo{
		Claims: Claims{
			Tenant:         tenant,
			ServiceAccount: sa,
			Project:        project,
		},
	}
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

// TestAccessRule_CanonicalDropsEmpty pins the fail-closed contract: a
// stray empty/whitespace entry in any allowlist (typically from a trailing
// comma in operator config) must NOT match a token whose claim is missing
// or empty. Otherwise the allowlist silently degrades to "no enforcement
// for callers without the claim".
func TestAccessRule_CanonicalDropsEmpty(t *testing.T) {
	rule := AccessRule{
		Scopes:          []string{"  email  ", "", "profile"},
		Tenants:         []string{"oa", "", "  ", "HwRd"},
		ServiceAccounts: []string{"sync@oa", ""},
		Projects:        []string{"p1", "  "},
	}.canonical()

	wantScopes := []string{"email", "profile"}
	if !slicesEqual(rule.Scopes, wantScopes) {
		t.Errorf("Scopes = %v, want %v", rule.Scopes, wantScopes)
	}
	wantTenants := []string{"oa", "hwrd"}
	if !slicesEqual(rule.Tenants, wantTenants) {
		t.Errorf("Tenants = %v, want %v", rule.Tenants, wantTenants)
	}
	if !slicesEqual(rule.ServiceAccounts, []string{"sync@oa"}) {
		t.Errorf("ServiceAccounts = %v", rule.ServiceAccounts)
	}
	if !slicesEqual(rule.Projects, []string{"p1"}) {
		t.Errorf("Projects = %v", rule.Projects)
	}

	// Token with missing claims must NOT pass the allowlists.
	if _, ok := rule.checkClaims(newInfo("", "", "")); ok {
		t.Error("missing claims passed allowlists — fail-closed broken")
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
