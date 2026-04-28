package jwksauth

import (
	"strings"
	"testing"
)

func TestParseIssuerTenants_EmptyDisablesEnforcement(t *testing.T) {
	out, err := ParseIssuerTenants("", []string{"https://a", "https://b"})
	if err != nil {
		t.Fatalf("ParseIssuerTenants(\"\"): %v", err)
	}
	if out != nil {
		t.Errorf("empty input should return nil map, got %v", out)
	}
}

func TestParseIssuerTenants_HappyPath(t *testing.T) {
	known := []string{"https://a", "https://b"}
	out, err := ParseIssuerTenants("https://a=oa,hwrd;https://b=swrd", known)
	if err != nil {
		t.Fatalf("ParseIssuerTenants: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d issuers, want 2", len(out))
	}
	if got := out["https://a"]; len(got) != 2 || got[0] != "oa" || got[1] != "hwrd" {
		t.Errorf("https://a tenants = %v, want [oa hwrd]", got)
	}
	if got := out["https://b"]; len(got) != 1 || got[0] != "swrd" {
		t.Errorf("https://b tenants = %v, want [swrd]", got)
	}
}

func TestParseIssuerTenants_LowerCases(t *testing.T) {
	out, err := ParseIssuerTenants("https://a=OA,HwRd", []string{"https://a"})
	if err != nil {
		t.Fatalf("ParseIssuerTenants: %v", err)
	}
	got := out["https://a"]
	if len(got) != 2 || got[0] != "oa" || got[1] != "hwrd" {
		t.Errorf("tenants = %v, want lower-cased [oa hwrd]", got)
	}
}

func TestParseIssuerTenants_RejectsUnknownIssuer(t *testing.T) {
	_, err := ParseIssuerTenants("https://typo=oa", []string{"https://a"})
	if err == nil || !strings.Contains(err.Error(), "not a registered issuer") {
		t.Fatalf("error = %v, want 'not a registered issuer'", err)
	}
}

func TestParseIssuerTenants_RequiresEveryKnownIssuer(t *testing.T) {
	_, err := ParseIssuerTenants("https://a=oa", []string{"https://a", "https://b"})
	if err == nil || !strings.Contains(err.Error(), "missing from") {
		t.Fatalf("error = %v, want 'missing from'", err)
	}
}

func TestParseIssuerTenants_DistinguishesDuplicateFromOverlap(t *testing.T) {
	// Same issuer, same tenant twice — typo, not cross-issuer overlap.
	_, err := ParseIssuerTenants("https://a=oa,oa", []string{"https://a"})
	if err == nil || !strings.Contains(err.Error(), "drop the duplicate") {
		t.Fatalf("same-issuer dup: error = %v, want 'drop the duplicate'", err)
	}

	// Different issuers, same tenant — true cross-issuer overlap.
	_, err = ParseIssuerTenants("https://a=oa;https://b=oa", []string{"https://a", "https://b"})
	if err == nil || !strings.Contains(err.Error(), "multiple issuers") {
		t.Fatalf("cross-issuer overlap: error = %v, want 'multiple issuers'", err)
	}
}

func TestParseIssuerTenants_RejectsEmptyTenantList(t *testing.T) {
	_, err := ParseIssuerTenants("https://a=", []string{"https://a"})
	if err == nil || !strings.Contains(err.Error(), "no tenants") {
		t.Fatalf("error = %v, want 'no tenants'", err)
	}
}

func TestParseIssuerTenants_RejectsMalformedEntry(t *testing.T) {
	_, err := ParseIssuerTenants("https://a", []string{"https://a"})
	if err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("error = %v, want 'malformed'", err)
	}
}

func TestParseIssuerTenants_DuplicateIssuerInRaw(t *testing.T) {
	_, err := ParseIssuerTenants(
		"https://a=oa;https://a=hwrd",
		[]string{"https://a"},
	)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("error = %v, want 'duplicate'", err)
	}
}
