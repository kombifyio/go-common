// Role claim extraction from OIDC tokens.
//
// Auth0 delivers kombify platform roles via a namespaced custom claim set by
// a Post-Login Action:
//
//	"https://kombify.io/roles": ["global_admin"]
//
// Auth0 also surfaces flat "role" (string) and "roles" ([]string) claims in
// some legacy flows. This file provides extractors that understand both shapes
// and always return canonical kombify platform roles in descending privilege
// order.
//
// TypeScript counterpart:
//
//	@kombify/contracts — kombify-Core/packages/contracts/src/role-claims.ts
package role

import (
	"sort"
	"strings"
)

// DefaultRoleClaimNamespace is the canonical Auth0 custom-claim namespace
// for kombify platform roles. Set by the "kombify Role Claim" Post-Login
// Action.
const DefaultRoleClaimNamespace = "https://kombify.io/roles"

// ExtractRoleFromClaims returns the highest-priority known role from a
// decoded OIDC claim set. It inspects, in order:
//
//  1. The namespaced claim (default "https://kombify.io/roles"), expected
//     to be a []string (Auth0 Post-Login Action shape).
//  2. A flat "roles" claim ([]string or []any of strings) for legacy / Kong
//     header forwards.
//  3. A flat "role" claim (string) for single-role legacy tokens.
//
// Unknown role strings are ignored. If no valid kombify role is found, the
// default [User] role is returned so downstream code can rely on a non-empty
// value.
func ExtractRoleFromClaims(claims map[string]any, namespace string) Role {
	if namespace == "" {
		namespace = DefaultRoleClaimNamespace
	}
	all := extractAll(claims, namespace)
	if len(all) == 0 {
		return User
	}
	return all[0]
}

// ExtractAllRolesFromClaims returns every known kombify role present in the
// claim set, sorted in descending privilege order (highest first). Duplicate
// and unknown entries are removed. If no valid role is found, the result is
// [User] so callers always get a safe default.
func ExtractAllRolesFromClaims(claims map[string]any, namespace string) []Role {
	if namespace == "" {
		namespace = DefaultRoleClaimNamespace
	}
	all := extractAll(claims, namespace)
	if len(all) == 0 {
		return []Role{User}
	}
	return all
}

// extractAll is the shared worker: dedupe + validate + sort by hierarchy.
func extractAll(claims map[string]any, namespace string) []Role {
	if len(claims) == 0 {
		return nil
	}

	raw := make([]string, 0, 4)

	// 1. Namespaced claim (canonical shape).
	if v, ok := claims[namespace]; ok {
		raw = append(raw, coerceRoleValue(v)...)
	}

	// 2. Flat "roles".
	if v, ok := claims["roles"]; ok {
		raw = append(raw, coerceRoleValue(v)...)
	}

	// 3. Flat "role".
	if s, ok := claims["role"].(string); ok && s != "" {
		raw = append(raw, s)
	}

	if len(raw) == 0 {
		return nil
	}

	seen := make(map[Role]struct{}, len(raw))
	out := make([]Role, 0, len(raw))
	for _, s := range raw {
		r := Role(strings.TrimSpace(s))
		if !r.IsValid() {
			continue
		}
		if _, dup := seen[r]; dup {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}

	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Level() > out[j].Level()
	})
	return out
}

// coerceRoleValue normalizes common JSON shapes for a "roles-ish" claim
// value into a flat []string. Accepts []string, []any (with string
// members), and a single string.
func coerceRoleValue(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	default:
		return nil
	}
}
