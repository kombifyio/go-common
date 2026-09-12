// Package authsession implements stateless HS256-signed session tokens that
// kombify backend services issue to their own browser frontends after a
// successful login (OIDC code-flow via [authflow], or break-glass via
// [authlocal]). The upstream provider's ID token is verified by
// [oidcclient.Verifier]; this package mints a short-lived backend session
// token whose only purpose is to carry user + tenant + provider claims
// through subsequent API calls.
//
// Why a separate token instead of forwarding the provider ID token?
//  1. Backends add tenant_id from their own provisioning step.
//  2. The signing secret can be rotated independently of any IdP.
//  3. The frontend-API contract stays stable across providers.
//
// Donor: kombify-Techstack/pkg/v2/auth/session (lifted 2026-05-03 as part of
// the auth standardization; kept verbatim apart from the package rename).
package authsession

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Defaults.
const (
	DefaultIssuer   = "kombify"
	DefaultLifetime = 30 * time.Minute
)

// Errors returned by Manager.
var (
	ErrConfigInvalid = errors.New("authsession: invalid configuration")
	ErrInvalidToken  = errors.New("authsession: invalid token")
)

// Config configures the [Manager].
type Config struct {
	// Issuer is the `iss` claim. Defaults to [DefaultIssuer].
	Issuer string
	// Audience is the `aud` claim. Required: identifies the consuming
	// frontend audience (e.g. "techstack:frontend", "kombisim:frontend").
	Audience string
	// Secret is the HS256 signing secret. Must be at least 32 bytes.
	Secret []byte
	// Lifetime is how long issued tokens stay valid. Defaults to
	// [DefaultLifetime] (30 minutes).
	Lifetime time.Duration
	// ClockSkew is reserved for future use; currently the underlying JWT
	// library handles default skew.
	ClockSkew time.Duration
}

// Claims is the payload of a session token.
type Claims struct {
	Subject         string `json:"sub"`
	TenantID        string `json:"tid"`
	OrgID           string `json:"org,omitempty"`
	Email           string `json:"email,omitempty"`
	Provider        string `json:"prv,omitempty"`
	Role            string `json:"role,omitempty"`
	ReauthPurpose   string `json:"reauth_purpose,omitempty"`
	ReauthResource  string `json:"reauth_resource,omitempty"`
	AuthenticatedAt int64  `json:"auth_time,omitempty"`
	IssuedAt        int64  `json:"iat,omitempty"`
	Expires         int64  `json:"exp,omitempty"`
}

// Manager mints and verifies session tokens.
type Manager struct {
	cfg Config
}

// NewManager validates Config and returns a Manager.
func NewManager(cfg Config) (*Manager, error) {
	if strings.TrimSpace(cfg.Audience) == "" {
		return nil, fmt.Errorf("%w: audience is required", ErrConfigInvalid)
	}
	if len(cfg.Secret) < 32 {
		return nil, fmt.Errorf("%w: secret must be at least 32 bytes", ErrConfigInvalid)
	}
	if strings.TrimSpace(cfg.Issuer) == "" {
		cfg.Issuer = DefaultIssuer
	}
	if cfg.Lifetime <= 0 {
		cfg.Lifetime = DefaultLifetime
	}
	return &Manager{cfg: cfg}, nil
}

// Issue mints a signed session token from the given claim payload. Subject
// and TenantID are required.
func (m *Manager) Issue(c Claims) (string, error) {
	if strings.TrimSpace(c.Subject) == "" {
		return "", fmt.Errorf("%w: subject required", ErrInvalidToken)
	}
	if strings.TrimSpace(c.TenantID) == "" {
		return "", fmt.Errorf("%w: tenant_id required", ErrInvalidToken)
	}
	c.ReauthPurpose = strings.TrimSpace(c.ReauthPurpose)
	c.ReauthResource = strings.TrimSpace(c.ReauthResource)
	if !validReauthBinding(c.ReauthPurpose, c.ReauthResource, c.AuthenticatedAt) {
		return "", fmt.Errorf("%w: incomplete reauthentication binding", ErrInvalidToken)
	}
	now := time.Now()
	mc := jwt.MapClaims{
		"iss": m.cfg.Issuer,
		"aud": m.cfg.Audience,
		"sub": c.Subject,
		"tid": c.TenantID,
		"iat": now.Unix(),
		"exp": now.Add(m.cfg.Lifetime).Unix(),
	}
	if c.OrgID != "" {
		mc["org"] = c.OrgID
	}
	if c.Email != "" {
		mc["email"] = c.Email
	}
	if c.Provider != "" {
		mc["prv"] = c.Provider
	}
	if c.Role != "" {
		mc["role"] = c.Role
	}
	if c.ReauthPurpose != "" {
		mc["reauth_purpose"] = c.ReauthPurpose
		mc["reauth_resource"] = c.ReauthResource
		mc["auth_time"] = c.AuthenticatedAt
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, mc)
	return tok.SignedString(m.cfg.Secret)
}

// Verify parses and validates a session token previously issued by
// [Manager.Issue].
func (m *Manager) Verify(raw string) (*Claims, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, ErrInvalidToken
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"HS256"}))
	parsed, err := parser.ParseWithClaims(raw, jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
		return m.cfg.Secret, nil
	})
	if err != nil || !parsed.Valid {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	mc, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidToken
	}
	if iss, _ := mc["iss"].(string); iss != m.cfg.Issuer {
		return nil, fmt.Errorf("%w: issuer mismatch", ErrInvalidToken)
	}
	if !audMatches(mc["aud"], m.cfg.Audience) {
		return nil, fmt.Errorf("%w: audience mismatch", ErrInvalidToken)
	}
	out := &Claims{}
	out.Subject, _ = mc["sub"].(string)
	out.TenantID, _ = mc["tid"].(string)
	out.OrgID, _ = mc["org"].(string)
	out.Email, _ = mc["email"].(string)
	out.Provider, _ = mc["prv"].(string)
	out.Role, _ = mc["role"].(string)
	out.ReauthPurpose, _ = mc["reauth_purpose"].(string)
	out.ReauthResource, _ = mc["reauth_resource"].(string)
	if v, ok := mc["auth_time"].(float64); ok {
		out.AuthenticatedAt = int64(v)
	}
	if v, ok := mc["iat"].(float64); ok {
		out.IssuedAt = int64(v)
	}
	if v, ok := mc["exp"].(float64); ok {
		out.Expires = int64(v)
	}
	if out.Subject == "" || out.TenantID == "" {
		return nil, fmt.Errorf("%w: missing required claims", ErrInvalidToken)
	}
	if !validReauthBinding(out.ReauthPurpose, out.ReauthResource, out.AuthenticatedAt) {
		return nil, fmt.Errorf("%w: incomplete reauthentication binding", ErrInvalidToken)
	}
	return out, nil
}

func validReauthBinding(purpose, resource string, authenticatedAt int64) bool {
	bound := purpose != "" || resource != "" || authenticatedAt != 0
	return !bound || (purpose != "" && resource != "" && authenticatedAt > 0)
}

func audMatches(raw interface{}, expected string) bool {
	switch a := raw.(type) {
	case string:
		return a == expected
	case []interface{}:
		for _, x := range a {
			if s, ok := x.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}
