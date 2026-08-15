package authlocal

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/kombifyio/go-common/authsession"
)

// memStore is an in-memory Store for tests.
type memStore struct {
	mu  sync.Mutex
	rec *Record
}

func (m *memStore) Get(_ context.Context) (*Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rec == nil {
		return nil, nil
	}
	clone := *m.rec
	return &clone, nil
}

func (m *memStore) Save(_ context.Context, r *Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r == nil {
		m.rec = nil
		return nil
	}
	clone := *r
	m.rec = &clone
	return nil
}

func newTestService(t *testing.T) *Service {
	t.Helper()
	mgr, err := authsession.NewManager(authsession.Config{
		Audience: "test",
		Secret:   []byte("test-secret-test-secret-test-secret-32"),
	})
	if err != nil {
		t.Fatalf("session manager: %v", err)
	}
	svc, err := New(Config{
		Store:           &memStore{},
		Sessions:        mgr,
		DefaultTenantID: "default",
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc
}

func TestBootstrap_CreatesRecord(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	pwd, err := svc.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if pwd == "" {
		t.Fatal("expected non-empty bootstrap password")
	}
	pwd2, err := svc.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("bootstrap again: %v", err)
	}
	if pwd2 != "" {
		t.Fatal("expected empty password on second bootstrap")
	}
}

func TestReveal_HappyPath(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	pwd, err := svc.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	rev, err := svc.Reveal(ctx)
	if err != nil {
		t.Fatalf("reveal: %v", err)
	}
	if rev.Password != pwd {
		t.Fatalf("reveal mismatch: got %q want %q", rev.Password, pwd)
	}
	if rev.Email != BreakGlassEmail {
		t.Fatalf("email mismatch: %q", rev.Email)
	}
	if rev.Claimed {
		t.Fatal("expected unclaimed")
	}
	if _, err := svc.Reveal(ctx); !errors.Is(err, ErrPasswordExpired) {
		t.Fatalf("expected ErrPasswordExpired on second reveal, got %v", err)
	}
	st, err := svc.CurrentStatus(ctx)
	if err != nil {
		t.Fatalf("status after reveal: %v", err)
	}
	if st.HasPendingReveal {
		t.Fatalf("expected reveal envelope to be consumed, got %+v", st)
	}
}

func TestReveal_Expired(t *testing.T) {
	svc := newTestService(t)
	now := time.Now()
	svc.cfg.Now = func() time.Time { return now }
	ctx := context.Background()
	if _, err := svc.Bootstrap(ctx); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	svc.cfg.Now = func() time.Time { return now.Add(2 * PasswordEnvelopeTTL) }
	if _, err := svc.Reveal(ctx); !errors.Is(err, ErrPasswordExpired) {
		t.Fatalf("expected ErrPasswordExpired, got %v", err)
	}
}

func TestClaim_FirstWins(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	bootstrapPwd, err := svc.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if err := svc.Claim(ctx, ClaimRequest{
		CurrentPassword: bootstrapPwd,
		NewEmail:        "operator@example.com",
		NewPassword:     "supersecret123",
	}); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if err := svc.Claim(ctx, ClaimRequest{
		CurrentPassword: bootstrapPwd,
		NewPassword:     "anotherpassword",
	}); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("expected ErrAlreadyClaimed, got %v", err)
	}
	if _, err := svc.Reveal(ctx); !errors.Is(err, ErrPasswordExpired) {
		t.Fatalf("expected ErrPasswordExpired post-claim, got %v", err)
	}
}

func TestClaim_WrongCurrentPassword(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	if _, err := svc.Bootstrap(ctx); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if err := svc.Claim(ctx, ClaimRequest{
		CurrentPassword: "wrong",
		NewPassword:     "newsupersecret",
	}); !errors.Is(err, ErrInvalidCreds) {
		t.Fatalf("expected ErrInvalidCreds, got %v", err)
	}
}

func TestClaim_Locked(t *testing.T) {
	svc := newTestService(t)
	svc.cfg.ClaimLocked = true
	ctx := context.Background()
	if _, err := svc.Bootstrap(ctx); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if err := svc.Claim(ctx, ClaimRequest{
		CurrentPassword: "anything",
		NewPassword:     "newpassword",
	}); !errors.Is(err, ErrLockedByOperator) {
		t.Fatalf("expected ErrLockedByOperator, got %v", err)
	}
}

func TestAuthenticate_HappyAndFail(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	pwd, err := svc.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	claims, err := svc.Authenticate(ctx, BreakGlassEmail, pwd)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if claims.Email != BreakGlassEmail {
		t.Fatalf("claim email: %q", claims.Email)
	}
	if claims.Provider != DefaultProviderID {
		t.Fatalf("provider: %q", claims.Provider)
	}
	if _, err := svc.Authenticate(ctx, BreakGlassEmail, "wrong"); !errors.Is(err, ErrInvalidCreds) {
		t.Fatalf("expected ErrInvalidCreds, got %v", err)
	}
}

func TestCurrentStatus(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	st, err := svc.CurrentStatus(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.Initialized {
		t.Fatal("expected uninitialised before bootstrap")
	}
	if _, err := svc.Bootstrap(ctx); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	st, err = svc.CurrentStatus(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !st.Initialized || st.Claimed || !st.HasPendingReveal {
		t.Fatalf("unexpected status: %+v", st)
	}
}
