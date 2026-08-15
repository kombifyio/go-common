// Package servicecall provides authenticated service-to-service HTTP calls
// within the kombify operator-managed network.
//
// Standards reference: kombify Core/standards/API-COMMUNICATION-ARCHITECTURE.md §4.
//
// Why HS256 shared-secret and not Auth0 M2M:
//   - operator-managed network is already isolated; auth here is for caller
//     identification (audit, authz), not traffic protection.
//   - Auth0 M2M roundtrips add 50-200ms + rate-limit risk per request.
//   - A shared secret with dual-key rotation (analogous to EDGE_AUTH_SECRET)
//     delivers identity at zero latency cost.
//
// Secret lifecycle:
//   - SERVICE_AUTH_SECRET       (primary, the configured secret source: kombify-io/prd)
//   - SERVICE_AUTH_SECRET_NEXT  (optional, active during 180-day rotation)
//
// Identity forwarding:
//   - Tokens may carry an OnBehalfOf claim that describes the end user the
//     caller is acting for. The receiving middleware promotes this into
//     identity.Identity so downstream handlers use identity.FromContext()
//     uniformly — regardless of whether the request entered via the Edge
//     or via another service.
//
// See also: edgeauth (Edge->Origin trust), toolauth (desktop tools),
// nodeauth (Sim user-nodes, Phase B).
package servicecall

import (
	"context"
	"time"
)

// HeaderServiceAuth is the HTTP header carrying the service-call JWT.
// Deliberately distinct from Authorization so end-user Bearer tokens and
// service-call tokens can coexist on the same request if needed.
const HeaderServiceAuth = "X-Kombify-Service-Auth"

// DefaultTokenTTL is the lifetime of issued service-call tokens.
// Short-lived by design: tokens are cheap to re-issue and do not need
// revocation infrastructure.
const DefaultTokenTTL = 5 * time.Minute

// clockSkewTolerance is the tolerated difference between issuer and
// verifier clocks when checking Iat.
const clockSkewTolerance = 30 * time.Second

// OnBehalfOf carries end-user context when a service call is made on a
// user's behalf. Promoted into identity.Identity at the receiving side.
type OnBehalfOf struct {
	Sub   string   `json:"sub,omitempty"`
	OrgID string   `json:"org_id,omitempty"`
	Email string   `json:"email,omitempty"`
	Tier  string   `json:"tier,omitempty"`
	Roles []string `json:"roles,omitempty"`
}

// Claims are the JWT claims carried in a service-call token.
type Claims struct {
	Iss        string      `json:"iss"`
	Aud        string      `json:"aud"`
	Iat        int64       `json:"iat"`
	Exp        int64       `json:"exp"`
	Svc        string      `json:"svc"`
	OnBehalfOf *OnBehalfOf `json:"on_behalf_of,omitempty"`
	RequestID  string      `json:"req_id,omitempty"`
}

// Caller is the verified caller identity after middleware validation.
type Caller struct {
	Service    string
	OnBehalfOf *OnBehalfOf
	RequestID  string
	IssuedAt   time.Time
	ExpiresAt  time.Time
}

// Config governs both client and middleware behaviour. Fields used by
// only one side are noted.
type Config struct {
	// ServiceName is the short id of the local service (e.g. "cloud", "ai").
	// Used as iss on outbound tokens and as the expected aud on inbound.
	ServiceName string

	// Target is the short id of the remote service. Client-side only.
	Target string

	// Secret is the primary HS256 signing secret (base64 or raw text).
	// Outbound tokens are always signed with Secret; inbound tokens are
	// verified against Secret first, then SecretNext if set.
	Secret string

	// SecretNext is the optional "next" secret active during rotation.
	SecretNext string

	// TokenTTL overrides DefaultTokenTTL. Client-side only.
	TokenTTL time.Duration

	// AllowedCallers is an optional whitelist of caller svc ids. When non-
	// empty, tokens whose Svc claim is not in the list are rejected with
	// 403 by the middleware. Middleware-side only.
	AllowedCallers []string

	// Enabled turns the middleware on. Defaults false so self-hosted
	// builds without SERVICE_AUTH_SECRET keep working.
	Enabled bool
}

type callerContextKey struct{}

// NewContext stores a Caller in ctx.
func NewContext(ctx context.Context, c *Caller) context.Context {
	return context.WithValue(ctx, callerContextKey{}, c)
}

// FromContext retrieves the verified Caller from ctx. Returns nil if none.
func FromContext(ctx context.Context) *Caller {
	if ctx == nil {
		return nil
	}
	c, _ := ctx.Value(callerContextKey{}).(*Caller)
	return c
}

// IsServiceCall reports whether the request was authenticated as a
// service-to-service call.
func IsServiceCall(ctx context.Context) bool {
	return FromContext(ctx) != nil
}
