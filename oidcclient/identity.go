package oidcclient

import (
	"strings"

	"github.com/kombifyio/go-common/identity"
)

// IdentityFromClaims projects an OIDC [Claims] onto a
// [identity.Identity]. The mapping is intentionally simple — services that
// need richer mapping (per-tenant role tables, group→role rewrites) should
// post-process the returned value.
//
// Claim sources, in priority order:
//
//   - UserID  ← `sub`
//   - Email   ← `email`
//   - OrgID   ← `org_id` || `org` || `project_id` (raw claim)
//   - Tier    ← `tier` || `plan` (raw claim)
//   - Roles   ← `roles` (raw claim, []string or comma-separated string)
//     || single `role` claim
//
// Returns nil if claims is nil.
func IdentityFromClaims(c *Claims) *identity.Identity {
	if c == nil {
		return nil
	}
	id := &identity.Identity{
		UserID: strings.TrimSpace(c.Subject),
		Email:  strings.TrimSpace(c.Email),
	}
	id.OrgID = firstStringClaim(c.Raw, "org_id", "org", "project_id")
	id.Tier = firstStringClaim(c.Raw, "tier", "plan")
	id.Roles = rolesFromClaims(c.Raw)
	return id
}

func firstStringClaim(raw map[string]interface{}, keys ...string) string {
	if raw == nil {
		return ""
	}
	for _, k := range keys {
		if v, ok := raw[k]; ok {
			if s, ok := v.(string); ok {
				if t := strings.TrimSpace(s); t != "" {
					return t
				}
			}
		}
	}
	return ""
}

func rolesFromClaims(raw map[string]interface{}) []string {
	if raw == nil {
		return nil
	}
	if v, ok := raw["roles"]; ok {
		switch t := v.(type) {
		case []interface{}:
			out := make([]string, 0, len(t))
			for _, x := range t {
				if s, ok := x.(string); ok {
					if r := strings.TrimSpace(s); r != "" {
						out = append(out, r)
					}
				}
			}
			if len(out) > 0 {
				return out
			}
		case string:
			out := []string{}
			for _, r := range strings.Split(t, ",") {
				if s := strings.TrimSpace(r); s != "" {
					out = append(out, s)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	if v, ok := raw["role"]; ok {
		if s, ok := v.(string); ok {
			if r := strings.TrimSpace(s); r != "" {
				return []string{r}
			}
		}
	}
	return nil
}
