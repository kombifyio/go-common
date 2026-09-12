package role

import (
	"testing"
)

func TestIsStaff(t *testing.T) {
	tests := []struct {
		role Role
		want bool
	}{
		{GlobalAdmin, true},
		{Admin, true}, // regression: Admin was missing from IsStaff (platform-ytmy.8.2)
		{Developer, true},
		{Manager, true},
		{User, false},
		{Role("unknown"), false},
		{Role(""), false},
	}
	for _, tt := range tests {
		if got := tt.role.IsStaff(); got != tt.want {
			t.Errorf("IsStaff(%q) = %v, want %v", tt.role, got, tt.want)
		}
	}
}

func TestExtractRoleFromClaimsAdmin(t *testing.T) {
	// regression: "admin" tokens were silently degraded to "user" before the
	// Admin role existed in the canonical set.
	claims := map[string]any{
		DefaultRoleClaimNamespace: []string{"admin"},
	}
	if got := ExtractRoleFromClaims(claims, ""); got != Admin {
		t.Errorf("ExtractRoleFromClaims(admin) = %q, want %q", got, Admin)
	}
}

func TestPlanCompatibilityAliases(t *testing.T) {
	// regression: business was a separate tier (50) above ayn (40) — drift
	// against the edge normalizer where business -> ayn (platform-ytmy.8.3).
	if Business.Level() != Ayn.Level() {
		t.Errorf("Business.Level() = %d, want Ayn level %d", Business.Level(), Ayn.Level())
	}
	if AllYouNeed.Level() != Ayn.Level() {
		t.Errorf("AllYouNeed.Level() = %d, want Ayn level %d", AllYouNeed.Level(), Ayn.Level())
	}
	if !Business.AtLeast(Ayn) || !Ayn.AtLeast(Business) {
		t.Error("Business and Ayn must rank identically")
	}
	if ProPlus.Level() != Pro.Level() {
		t.Errorf("ProPlus.Level() = %d, want Pro level %d", ProPlus.Level(), Pro.Level())
	}
	if !ProPlus.AtLeast(Pro) || !Pro.AtLeast(ProPlus) {
		t.Error("ProPlus and Pro must rank identically")
	}
}

// TestParsePlanMirrorsEdgeAliases keeps the Go alias table in lockstep with
// PLAN_TIER_ALIASES in kombify-Gateway/cloudflare-edge/src/entitlements.ts.
func TestParsePlanMirrorsEdgeAliases(t *testing.T) {
	tests := []struct {
		in   string
		want Plan
	}{
		{"anonymous", Anonymous},
		{"public", Anonymous},
		{"free", Free},
		{"starter", Starter},
		{"pro", Pro},
		{"premium", Pro},
		{"pro_plus", Pro},
		{"proplus", Pro},
		{"all_you_need", Ayn},
		{"all_you_need_tier", Ayn},
		{"ayn", Ayn},
		{"business", Ayn},
		{"enterprise", Ayn},
		{"team", Ayn},
		{"staff", Ayn},
		{"internal", Ayn},
		// normalization behavior
		{" PRO ", Pro},
		{"Pro-Plus", Pro},
		{"ALL-YOU-NEED", Ayn},
	}
	for _, tt := range tests {
		got, ok := ParsePlan(tt.in)
		if !ok {
			t.Errorf("ParsePlan(%q) not ok, want %q", tt.in, tt.want)
			continue
		}
		if got != tt.want {
			t.Errorf("ParsePlan(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParsePlanUnknown(t *testing.T) {
	if _, ok := ParsePlan("platinum"); ok {
		t.Error("ParsePlan(platinum) must not be ok")
	}
	if _, ok := ParsePlan(""); ok {
		t.Error("ParsePlan(\"\") must not be ok")
	}
	if got := NormalizePlan("platinum"); got != Free {
		t.Errorf("NormalizePlan(platinum) = %q, want %q (edge default)", got, Free)
	}
}
