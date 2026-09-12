// Package authlocal implements username+password authentication for kombify
// backends backed by a single break-glass admin record.
//
// Self-hosted kombify tools (TechStack, Sim, …) deliberately avoid running
// their own multi-user management. End users live in an OIDC provider
// (Pocket ID, Auth0, PocketBase) once one is provisioned. The local package
// only exists to bootstrap the very first admin so the operator can log in
// before any IdP is configured.
//
// Pattern:
//   - bcrypt.DefaultCost password hashing
//   - HS256 session JWT minted by [authsession.Manager] (same cookie as OIDC)
//   - Show-once break-glass password persisted with a 1h envelope
//   - First-claim-wins handover from bootstrap to operator-owned creds
//
// Donor: kombify-Techstack/pkg/v2/auth/local (lifted 2026-05-03 and rebound
// from techstack-internal session/authmw to shared authsession +
// oidcclient).
package authlocal

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kombifyio/go-common/authsession"
)

// BreakGlassEmail is the well-known email of the auto-bootstrapped admin.
const BreakGlassEmail = "breakglass@local"

// BreakGlassRecordID is the singleton row id used by PocketBase-backed
// stores (must be at least 15 characters to satisfy PB id min-length).
const BreakGlassRecordID = "breakglassroot0"

// PasswordEnvelopeTTL is how long the auto-generated break-glass password is
// retrievable via Reveal() before being permanently scrubbed.
const PasswordEnvelopeTTL = 1 * time.Hour

// DefaultProviderID is the logical provider id the local credential method
// returns through the discovery endpoint.
const DefaultProviderID = "breakglass"

// Errors.
var (
	ErrInvalidConfig    = errors.New("authlocal: invalid configuration")
	ErrInvalidCreds     = errors.New("authlocal: invalid credentials")
	ErrAlreadyClaimed   = errors.New("authlocal: break-glass admin already claimed")
	ErrNotFound         = errors.New("authlocal: break-glass admin not initialized")
	ErrPasswordExpired  = errors.New("authlocal: break-glass password no longer available")
	ErrLockedByOperator = errors.New("authlocal: break-glass claim is locked")
)

// Config configures a [Service].
type Config struct {
	// Store backs the singleton break-glass record. Required.
	Store Store
	// Sessions mints HS256 session JWTs identical to the OIDC callback path.
	// Required.
	Sessions *authsession.Manager
	// DefaultTenantID is stamped into the session claims for break-glass
	// logins. Defaults to "default".
	DefaultTenantID string
	// BootstrapEmail overrides the default break-glass email
	// ([BreakGlassEmail]) used by [Service.Bootstrap].
	BootstrapEmail string
	// SessionCookieName must match the cookie used by the OIDC flow so a
	// break-glass session is indistinguishable from an OIDC session.
	// Defaults to [authsession.DefaultSessionCookieName].
	SessionCookieName string
	// SessionCookieSecure controls the Secure flag on auth cookies.
	SessionCookieSecure bool
	// ClaimLocked refuses claims even when the record is still in bootstrap
	// state. Used to harden production after the legitimate admin has
	// claimed.
	ClaimLocked bool
	// Now is injectable for tests.
	Now func() time.Time
}

// Service is the local credential service.
type Service struct {
	cfg Config
	mu  sync.Mutex // serializes bootstrap+claim races
}

// New validates Config and returns a [Service].
func New(cfg Config) (*Service, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalidConfig)
	}
	if cfg.Sessions == nil {
		return nil, fmt.Errorf("%w: sessions manager is required", ErrInvalidConfig)
	}
	if strings.TrimSpace(cfg.DefaultTenantID) == "" {
		cfg.DefaultTenantID = "default"
	}
	if strings.TrimSpace(cfg.BootstrapEmail) == "" {
		cfg.BootstrapEmail = BreakGlassEmail
	}
	if strings.TrimSpace(cfg.SessionCookieName) == "" {
		cfg.SessionCookieName = authsession.DefaultSessionCookieName
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Service{cfg: cfg}, nil
}

// CookieName returns the configured session cookie name.
func (s *Service) CookieName() string { return s.cfg.SessionCookieName }

// CookieSecure returns whether the session cookie is marked Secure.
func (s *Service) CookieSecure() bool { return s.cfg.SessionCookieSecure }
