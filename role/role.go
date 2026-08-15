// Package role defines the canonical role and plan types for the kombify platform.
//
// Roles control authorization (what a user may do).
// Plans control entitlements (what features a user may access).
//
// Self-hosted tools (Stack, Sim, StackKits) may define their own local roles
// (e.g. viewer/user/admin). Platform roles only apply in SaaS context via
// Auth0; delivered to origins via the Cloudflare edge signed X-User-Roles header.
//
// Canonical SSOT: kombify-Core/standards/PLATFORM-CONSOLIDATION-PLAN.md §K1.
package role

import "strings"

// Role represents a platform-level authorization role.
// Stored in Auth0 project roles and propagated via the Cloudflare edge
// signed X-User-* header envelope (go-common/edgeauth).
type Role string

const (
	// GlobalAdmin is the single platform owner with unrestricted access.
	GlobalAdmin Role = "global_admin"
	// Admin is a Kombiverse Labs administrator; below GlobalAdmin, above Developer.
	// Added in canonical set 2026-06-05; previously defined only in Administration/Cloud/Desk locally.
	Admin Role = "admin"
	// Developer has near-admin access to Admin Center, Company Tools, and all kombify tools.
	Developer Role = "developer"
	// Manager is a Kombiverse Labs employee with access to Admin Center, Company Tools, and all kombify tools.
	Manager Role = "manager"
	// User is a standard end customer (B2C or B2B). Default role for all customers.
	User Role = "user"
)

// AllRoles lists every defined role in descending privilege order.
var AllRoles = []Role{GlobalAdmin, Admin, Developer, Manager, User}

// StaffRoles lists roles that grant access to Admin Center and Company Tools.
var StaffRoles = []Role{GlobalAdmin, Admin, Developer, Manager}

// roleHierarchy maps each role to a numeric level for comparison.
// Higher value = more privileges.
var roleHierarchy = map[Role]int{
	GlobalAdmin: 100,
	Admin:       90,
	Developer:   80,
	Manager:     60,
	User:        10,
}

// Level returns the numeric privilege level for a role.
// Unknown roles return 0.
func (r Role) Level() int {
	return roleHierarchy[r]
}

// AtLeast returns true if this role has at least the privilege level of target.
func (r Role) AtLeast(target Role) bool {
	return r.Level() >= target.Level()
}

// IsStaff returns true if this role is a staff role (any role in StaffRoles:
// global_admin, admin, developer, manager).
func (r Role) IsStaff() bool {
	for _, s := range StaffRoles {
		if r == s {
			return true
		}
	}
	return false
}

// IsValid returns true if this role is a known platform role.
func (r Role) IsValid() bool {
	_, ok := roleHierarchy[r]
	return ok
}

// String returns the string representation.
func (r Role) String() string {
	return string(r)
}

// Plan represents a subscription plan (entitlement tier).
// Canonical enum per kombify-Core/standards/ENTITLEMENTS-ARCHITECTURE.md §3 /
// BILLING-ENTITLEMENT-STANDARD.md: anonymous, free, starter, pro, ayn.
// Mirrors the Cloudflare edge normalizer
// (kombify-Gateway/cloudflare-edge/src/entitlements.ts).
type Plan string

const (
	// Anonymous is the pseudo-tier for unauthenticated access. It ranks
	// below Free and shares the lowest level with unknown plans.
	Anonymous Plan = "anonymous"
	Free      Plan = "free"
	Starter   Plan = "starter"
	Pro       Plan = "pro"
	ProPlus   Plan = "pro_plus" // Alias for Pro; accepted in IsValid/Level/ParsePlan.
	// Ayn is the canonical identifier for the "All You Need" plan tier.
	// Use Ayn in all new code. AllYouNeed and Business are backward-compat
	// aliases for persisted JWT/DB values — all three resolve to the same
	// level (kombify-Gateway ADR 0002: there is no separate business tier).
	Ayn        Plan = "ayn"
	AllYouNeed Plan = "all_you_need" // Alias for Ayn; accepted in IsValid/Level/ParsePlan.
	Business   Plan = "business"     // Alias for Ayn; accepted in IsValid/Level/ParsePlan.
)

// AllPlans lists the canonical plans in ascending tier order.
// Aliases (ProPlus, AllYouNeed, Business) are intentionally excluded.
var AllPlans = []Plan{Anonymous, Free, Starter, Pro, Ayn}

// planHierarchy maps each plan to a numeric level for comparison.
// ProPlus resolves to Pro; Ayn, AllYouNeed and Business resolve to the same level (30).
var planHierarchy = map[Plan]int{
	Anonymous:  -1,
	Free:       0,
	Starter:    10,
	Pro:        20,
	ProPlus:    20, // backward-compat alias
	Ayn:        30,
	AllYouNeed: 30, // backward-compat alias
	Business:   30, // backward-compat alias (was a separate tier 50 pre-ADR-0002)
}

// planAliases maps every accepted spelling to its canonical plan. Mirrors
// PLAN_TIER_ALIASES in kombify-Gateway/cloudflare-edge/src/entitlements.ts.
var planAliases = map[string]Plan{
	"anonymous":         Anonymous,
	"public":            Anonymous,
	"free":              Free,
	"starter":           Starter,
	"pro":               Pro,
	"premium":           Pro,
	"pro_plus":          Pro,
	"proplus":           Pro,
	"all_you_need":      Ayn,
	"all_you_need_tier": Ayn,
	"ayn":               Ayn,
	"business":          Ayn,
	"enterprise":        Ayn,
	"team":              Ayn,
	"staff":             Ayn,
	"internal":          Ayn,
}

// ParsePlan normalizes a raw tier string (JWT claim, X-User-Tier header, DB
// value) to its canonical plan. Matching is case-insensitive and treats '-'
// as '_'. ok is false for unknown values.
func ParsePlan(s string) (Plan, bool) {
	key := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "-", "_")
	p, ok := planAliases[key]
	return p, ok
}

// NormalizePlan is ParsePlan with the edge default: unknown values normalize
// to Free (the floor for an authenticated principal; unauthenticated traffic
// never reaches origins with a tier header).
func NormalizePlan(s string) Plan {
	if p, ok := ParsePlan(s); ok {
		return p
	}
	return Free
}

// Level returns the numeric tier level for a plan.
// Unknown plans return -1 (the Anonymous level — fail-closed).
func (p Plan) Level() int {
	if v, ok := planHierarchy[p]; ok {
		return v
	}
	return -1
}

// AtLeast returns true if this plan is at least the given tier.
func (p Plan) AtLeast(target Plan) bool {
	return p.Level() >= target.Level()
}

// IsValid returns true if this plan is a known plan.
func (p Plan) IsValid() bool {
	_, ok := planHierarchy[p]
	return ok
}

// String returns the string representation.
func (p Plan) String() string {
	return string(p)
}
