package authsession

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

func TestNewManagerValidatesConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"missing audience", Config{Secret: testSecret}},
		{"short secret", Config{Audience: "frontend", Secret: []byte("short")}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewManager(c.cfg); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestIssueAndVerifyRoundtrip(t *testing.T) {
	m, err := NewManager(Config{Audience: "frontend", Secret: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := m.Issue(Claims{Subject: "u-1", TenantID: "t-1", Email: "u@x", Provider: "primary", Role: "admin", ReauthPurpose: "server-terminal", ReauthResource: "server-1", AuthenticatedAt: 42})
	if err != nil {
		t.Fatal(err)
	}
	c, err := m.Verify(raw)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if c.Subject != "u-1" || c.TenantID != "t-1" || c.Provider != "primary" || c.Role != "admin" || c.ReauthPurpose != "server-terminal" || c.ReauthResource != "server-1" || c.AuthenticatedAt != 42 {
		t.Fatalf("unexpected: %+v", c)
	}
}

func TestIssueRejectsIncompleteReauthenticationBinding(t *testing.T) {
	m, _ := NewManager(Config{Audience: "frontend", Secret: testSecret})
	if _, err := m.Issue(Claims{Subject: "u", TenantID: "t", ReauthPurpose: "server-terminal"}); err == nil {
		t.Fatal("expected incomplete reauthentication binding to fail")
	}
}

func TestIssueRejectsMissingSubjectOrTenant(t *testing.T) {
	m, _ := NewManager(Config{Audience: "frontend", Secret: testSecret})
	if _, err := m.Issue(Claims{TenantID: "t"}); err == nil {
		t.Fatal("expected subject error")
	}
	if _, err := m.Issue(Claims{Subject: "u"}); err == nil {
		t.Fatal("expected tenant error")
	}
}

func TestVerifyRejectsTamperedToken(t *testing.T) {
	m, _ := NewManager(Config{Audience: "frontend", Secret: testSecret})
	raw, _ := m.Issue(Claims{Subject: "u", TenantID: "t"})
	tampered := raw[:len(raw)-2] + "xx"
	if _, err := m.Verify(tampered); err == nil {
		t.Fatal("expected error on tampered token")
	}
	if _, err := m.Verify(""); err == nil {
		t.Fatal("expected error on empty")
	}
	if _, err := m.Verify(strings.Repeat("a.", 3)); err == nil {
		t.Fatal("expected error on garbage")
	}
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	m, _ := NewManager(Config{Audience: "frontend", Secret: testSecret, Lifetime: time.Millisecond})
	raw, _ := m.Issue(Claims{Subject: "u", TenantID: "t"})
	time.Sleep(5 * time.Millisecond)
	if _, err := m.Verify(raw); err == nil {
		t.Fatal("expected expired error")
	}
}

func TestVerifyRejectsWrongAudience(t *testing.T) {
	a, _ := NewManager(Config{Audience: "frontend", Secret: testSecret})
	b, _ := NewManager(Config{Audience: "other", Secret: testSecret})
	raw, _ := a.Issue(Claims{Subject: "u", TenantID: "t"})
	if _, err := b.Verify(raw); err == nil {
		t.Fatal("expected audience mismatch")
	}
}

func TestMiddlewareAcceptsCookie(t *testing.T) {
	m, _ := NewManager(Config{Audience: "frontend", Secret: testSecret})
	raw, _ := m.Issue(Claims{Subject: "u", TenantID: "t"})
	mw := NewMiddleware(m)
	called := false
	h := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		c, err := ClaimsFrom(r.Context())
		if err != nil || c.Subject != "u" {
			t.Fatalf("claims: %v %+v", err, c)
		}
		tid, _ := TenantFrom(r.Context())
		if tid != "t" {
			t.Fatalf("tenant=%q", tid)
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: DefaultSessionCookieName, Value: raw})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called {
		t.Fatal("handler not called")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestMiddlewareAcceptsBearer(t *testing.T) {
	m, _ := NewManager(Config{Audience: "frontend", Secret: testSecret})
	raw, _ := m.Issue(Claims{Subject: "u", TenantID: "t"})
	mw := NewMiddleware(m, WithCookieName("custom_cookie"))
	if mw.CookieName() != "custom_cookie" {
		t.Fatalf("cookie name=%q", mw.CookieName())
	}
	h := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestMiddlewareRejectsMissingToken(t *testing.T) {
	m, _ := NewManager(Config{Audience: "frontend", Secret: testSecret})
	mw := NewMiddleware(m)
	h := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not be called")
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestSetClearSessionCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	SetSessionCookie(rec, "k", "v", true)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "k" || cookies[0].Value != "v" || !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatalf("set cookie=%+v", cookies)
	}
	rec = httptest.NewRecorder()
	ClearSessionCookie(rec, "k", true)
	cookies = rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge != -1 {
		t.Fatalf("clear cookie=%+v", cookies)
	}
}

func TestSessionCookieLocalHTTPKeepsNonTransportProtections(t *testing.T) {
	rec := httptest.NewRecorder()
	SetSessionCookie(rec, "k", "v", false)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%+v", cookies)
	}
	if cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("local HTTP cookie attributes=%+v", cookies[0])
	}
}

func TestClaimsFromMissing(t *testing.T) {
	if _, err := ClaimsFrom(context.Background()); err == nil {
		t.Fatal("expected ErrMissingClaims")
	}
}
