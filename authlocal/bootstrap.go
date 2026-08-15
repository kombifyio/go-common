package authlocal

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kombifyio/go-common/authsession"
)

// Bootstrap ensures the break-glass admin record exists.
//
// On first run it creates a record with the configured BootstrapEmail and a
// freshly generated 18-byte password (~24 char base64), persists the bcrypt
// hash, and stores the plaintext in a 1h show-once envelope. On subsequent
// runs it is a no-op.
//
// Returns the generated plaintext password if a new record was created,
// otherwise the empty string.
func (s *Service) Bootstrap(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.cfg.Store.Get(ctx)
	if err != nil {
		return "", fmt.Errorf("get record: %w", err)
	}
	if rec != nil && rec.PasswordHash != "" {
		// Already bootstrapped; if the envelope expired, scrub it.
		if !rec.ShowUntil.IsZero() && s.cfg.Now().After(rec.ShowUntil) {
			rec.ShowPassword = ""
			rec.ShowUntil = time.Time{}
			if saveErr := s.cfg.Store.Save(ctx, rec); saveErr != nil {
				return "", fmt.Errorf("scrub envelope: %w", saveErr)
			}
		}
		return "", nil
	}

	password, err := generateSecureToken(18)
	if err != nil {
		return "", err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return "", err
	}
	now := s.cfg.Now()
	fresh := &Record{
		Email:        s.cfg.BootstrapEmail,
		PasswordHash: hash,
		ShowPassword: password,
		ShowUntil:    now.Add(PasswordEnvelopeTTL),
		Claimed:      false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.cfg.Store.Save(ctx, fresh); err != nil {
		return "", fmt.Errorf("save record: %w", err)
	}
	return password, nil
}

// RevealResult is the show-once envelope payload.
type RevealResult struct {
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	ExpiresAt time.Time `json:"expires_at"`
	Claimed   bool      `json:"claimed"`
}

// Reveal returns the bootstrap password if the envelope is still alive.
// Calling Reveal on an expired or already-consumed envelope returns
// [ErrPasswordExpired].
func (s *Service) Reveal(ctx context.Context) (*RevealResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.cfg.Store.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("get record: %w", err)
	}
	if rec == nil || rec.PasswordHash == "" {
		return nil, ErrNotFound
	}
	if rec.Claimed {
		return nil, ErrPasswordExpired
	}
	if rec.ShowPassword == "" {
		return nil, ErrPasswordExpired
	}
	if !rec.ShowUntil.IsZero() && s.cfg.Now().After(rec.ShowUntil) {
		// Auto-scrub expired envelope.
		rec.ShowPassword = ""
		rec.ShowUntil = time.Time{}
		if err := s.cfg.Store.Save(ctx, rec); err != nil {
			return nil, fmt.Errorf("scrub envelope: %w", err)
		}
		return nil, ErrPasswordExpired
	}
	result := &RevealResult{
		Email:     rec.Email,
		Password:  rec.ShowPassword,
		ExpiresAt: rec.ShowUntil,
		Claimed:   rec.Claimed,
	}
	rec.ShowPassword = ""
	rec.ShowUntil = time.Time{}
	rec.UpdatedAt = s.cfg.Now()
	if err := s.cfg.Store.Save(ctx, rec); err != nil {
		return nil, fmt.Errorf("consume envelope: %w", err)
	}
	return result, nil
}

// ClaimRequest is the input to [Service.Claim].
type ClaimRequest struct {
	// CurrentPassword is the bootstrap password the operator received.
	CurrentPassword string
	// NewEmail optionally renames the admin to a personal address.
	NewEmail string
	// NewPassword is the operator's chosen permanent secret.
	NewPassword string
}

// Claim rotates the break-glass record from bootstrap state to its final
// operator-owned values. First-POST-wins: subsequent calls return
// [ErrAlreadyClaimed].
//
// If [Config.ClaimLocked] is set, claiming is refused even when the record
// is still in bootstrap state — used to harden production where the
// operator has already claimed and wants to make absolutely sure no second
// claim slips in.
func (s *Service) Claim(ctx context.Context, req ClaimRequest) error {
	if s.cfg.ClaimLocked {
		return ErrLockedByOperator
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.cfg.Store.Get(ctx)
	if err != nil {
		return fmt.Errorf("get record: %w", err)
	}
	if rec == nil || rec.PasswordHash == "" {
		return ErrNotFound
	}
	if rec.Claimed {
		return ErrAlreadyClaimed
	}
	if err := verifyPassword(rec.PasswordHash, req.CurrentPassword); err != nil {
		return err
	}
	newPwd := strings.TrimSpace(req.NewPassword)
	if newPwd == "" {
		return fmt.Errorf("%w: new password required", ErrInvalidCreds)
	}
	hash, err := hashPassword(newPwd)
	if err != nil {
		return err
	}
	email := strings.TrimSpace(req.NewEmail)
	if email == "" {
		email = rec.Email
	}
	now := s.cfg.Now()
	rec.Email = email
	rec.PasswordHash = hash
	rec.ShowPassword = ""
	rec.ShowUntil = time.Time{}
	rec.Claimed = true
	rec.UpdatedAt = now
	if err := s.cfg.Store.Save(ctx, rec); err != nil {
		return fmt.Errorf("save record: %w", err)
	}
	return nil
}

// Authenticate verifies a login attempt and returns [authsession.Claims] if
// valid.
func (s *Service) Authenticate(ctx context.Context, email, password string) (authsession.Claims, error) {
	rec, err := s.cfg.Store.Get(ctx)
	if err != nil {
		return authsession.Claims{}, fmt.Errorf("get record: %w", err)
	}
	if rec == nil || rec.PasswordHash == "" {
		return authsession.Claims{}, ErrInvalidCreds
	}
	if !strings.EqualFold(strings.TrimSpace(email), strings.TrimSpace(rec.Email)) {
		return authsession.Claims{}, ErrInvalidCreds
	}
	if err := verifyPassword(rec.PasswordHash, password); err != nil {
		if errors.Is(err, ErrInvalidCreds) {
			return authsession.Claims{}, ErrInvalidCreds
		}
		return authsession.Claims{}, err
	}
	return authsession.Claims{
		Subject:  "breakglass:" + BreakGlassRecordID,
		TenantID: s.cfg.DefaultTenantID,
		Email:    rec.Email,
		Provider: DefaultProviderID,
		Role:     "admin",
	}, nil
}

// Status reports the current bootstrap/claim state used by the methods
// discovery endpoint and the setup wizard.
type Status struct {
	Initialized      bool      `json:"initialized"`
	Claimed          bool      `json:"claimed"`
	Email            string    `json:"email,omitempty"`
	HasPendingReveal bool      `json:"has_pending_reveal"`
	RevealExpiresAt  time.Time `json:"reveal_expires_at,omitempty"`
	Locked           bool      `json:"locked"`
}

// CurrentStatus inspects the record without exposing secrets.
func (s *Service) CurrentStatus(ctx context.Context) (Status, error) {
	rec, err := s.cfg.Store.Get(ctx)
	if err != nil {
		return Status{}, fmt.Errorf("get record: %w", err)
	}
	if rec == nil || rec.PasswordHash == "" {
		return Status{Initialized: false, Locked: s.cfg.ClaimLocked}, nil
	}
	pending := rec.ShowPassword != "" && (rec.ShowUntil.IsZero() || s.cfg.Now().Before(rec.ShowUntil))
	return Status{
		Initialized:      true,
		Claimed:          rec.Claimed,
		Email:            rec.Email,
		HasPendingReveal: pending,
		RevealExpiresAt:  rec.ShowUntil,
		Locked:           s.cfg.ClaimLocked,
	}, nil
}
