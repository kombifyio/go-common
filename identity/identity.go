// Package identity provides shared types for edge-injected user identity.
// In SaaS mode, the Cloudflare Edge Router (formerly Kong Gateway) validates
// the incoming JWT and injects X-User-ID, X-Org-ID, X-User-Email, and
// X-User-Roles headers. This package makes those values available throughout
// the request lifecycle via context.
//
// Use edgeauth.Middleware (CF Edge Router) or kong.Middleware (Kong) to
// populate the identity into context before calling FromContext().
package identity

import (
	"context"
	"strings"
)

type contextKey struct{}

// Identity holds the user identity injected by the Cloudflare Edge Router
// (formerly Kong Gateway) after Auth0 JWT validation.
type Identity struct {
	UserID string   `json:"user_id,omitempty"`
	OrgID  string   `json:"org_id,omitempty"`
	Email  string   `json:"email,omitempty"`
	Tier   string   `json:"tier,omitempty"`
	Roles  []string `json:"roles,omitempty"`
}

// IsAuthenticated returns true if at least a UserID is present.
func (id *Identity) IsAuthenticated() bool {
	return id != nil && id.UserID != ""
}

// HasRole checks if the identity has a specific role (case-insensitive).
func (id *Identity) HasRole(role string) bool {
	if id == nil {
		return false
	}
	for _, r := range id.Roles {
		if strings.EqualFold(strings.TrimSpace(r), role) {
			return true
		}
	}
	return false
}

// NewContext returns a new context with the Identity stored.
func NewContext(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// FromContext retrieves the Identity from context. Returns nil if not present.
func FromContext(ctx context.Context) *Identity {
	if ctx == nil {
		return nil
	}
	id, _ := ctx.Value(contextKey{}).(*Identity)
	return id
}

// FromHeaders extracts an Identity from HTTP headers.
func FromHeaders(get func(string) string) *Identity {
	id := &Identity{
		UserID: strings.TrimSpace(get("X-User-ID")),
		OrgID:  strings.TrimSpace(get("X-Org-ID")),
		Email:  strings.TrimSpace(get("X-User-Email")),
		Tier:   strings.TrimSpace(get("X-User-Tier")),
	}
	if roles := strings.TrimSpace(get("X-User-Roles")); roles != "" {
		for _, r := range strings.Split(roles, ",") {
			if t := strings.TrimSpace(r); t != "" {
				id.Roles = append(id.Roles, t)
			}
		}
	}
	return id
}
