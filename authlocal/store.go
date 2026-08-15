package authlocal

import (
	"context"
	"time"
)

// Record is the break-glass admin singleton record.
type Record struct {
	// Email is the login identifier. Bootstrap creates it as
	// [BreakGlassEmail] (or [Config.BootstrapEmail]) but Claim() lets the
	// operator rename it.
	Email string
	// PasswordHash is bcrypt(password). Empty means the record has not been
	// initialised yet.
	PasswordHash string
	// ShowPassword carries the plaintext password while the envelope is
	// alive. Empty after Reveal() consumed it or PasswordEnvelopeTTL elapsed.
	ShowPassword string
	// ShowUntil is the envelope expiry. Zero means no pending envelope.
	ShowUntil time.Time
	// Claimed reports whether the operator has rotated the bootstrap secret
	// at least once via Claim(). After claim, Reveal() returns 410.
	Claimed bool
	// CreatedAt and UpdatedAt are auto-stamped by the store.
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Store persists the singleton break-glass admin record.
//
// Implementations must serialise concurrent writes; Get may return a copy.
// Save replaces the entire record (single-row collection semantics).
type Store interface {
	// Get returns the current record or nil if it has never been written.
	Get(ctx context.Context) (*Record, error)
	// Save creates or replaces the singleton record.
	Save(ctx context.Context, r *Record) error
}
