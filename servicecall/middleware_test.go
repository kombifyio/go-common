package servicecall

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kombifyio/go-common/identity"
)

func newHandler(t *testing.T, wantCaller bool, wantIdentitySub string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := FromContext(r.Context())
		if wantCaller && c == nil {
			t.Errorf("expected Caller in ctx")
		}
		if !wantCaller && c != nil {
			t.Errorf("unexpected Caller in ctx: %+v", c)
		}
		if wantIdentitySub != "" {
			id := identity.FromContext(r.Context())
			if id == nil || id.UserID != wantIdentitySub {
				t.Errorf("identity promotion failed: got %+v, want UserID=%s", id, wantIdentitySub)
			}
		}
		w.WriteHeader(http.StatusOK)
	})
}

func TestMiddleware_Disabled_PassesThrough(t *testing.T) {
	cfg := Config{ServiceName: "ai", Secret: "s", Enabled: false}
	h := Middleware(cfg)(newHandler(t, false, ""))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(HeaderServiceAuth, "anything")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestMiddleware_NoHeader_PassesThrough(t *testing.T) {
	cfg := Config{ServiceName: "ai", Secret: "s", Enabled: true}
	h := Middleware(cfg)(newHandler(t, false, ""))

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestMiddleware_ValidToken_PromotesIdentity(t *testing.T) {
	secret := "s"
	cfg := Config{ServiceName: "ai", Secret: secret, Enabled: true}
	obo := &OnBehalfOf{Sub: "user_1", OrgID: "org_a", Email: "u@x", Roles: []string{"user"}}
	tok, err := IssueToken(Config{ServiceName: "cloud", Secret: secret, TokenTTL: time.Minute}, "ai", obo, "req-1")
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	h := Middleware(cfg)(newHandler(t, true, "user_1"))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(HeaderServiceAuth, tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMiddleware_InvalidToken_401(t *testing.T) {
	cfg := Config{ServiceName: "ai", Secret: "s", Enabled: true}
	h := Middleware(cfg)(newHandler(t, false, ""))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(HeaderServiceAuth, "not.a.jwt")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestMiddleware_WrongAudience_401(t *testing.T) {
	secret := "s"
	// Issue a token TO "other", not "ai"
	tok, _ := IssueToken(Config{ServiceName: "cloud", Secret: secret, TokenTTL: time.Minute}, "other", nil, "")

	cfg := Config{ServiceName: "ai", Secret: secret, Enabled: true}
	h := Middleware(cfg)(newHandler(t, false, ""))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(HeaderServiceAuth, tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestMiddleware_CallerNotAllowed_403(t *testing.T) {
	secret := "s"
	tok, _ := IssueToken(Config{ServiceName: "cloud", Secret: secret, TokenTTL: time.Minute}, "ai", nil, "")

	cfg := Config{
		ServiceName:    "ai",
		Secret:         secret,
		Enabled:        true,
		AllowedCallers: []string{"administration", "techstack"},
	}
	h := Middleware(cfg)(newHandler(t, false, ""))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(HeaderServiceAuth, tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMiddleware_AllowedCaller_OK(t *testing.T) {
	secret := "s"
	tok, _ := IssueToken(Config{ServiceName: "cloud", Secret: secret, TokenTTL: time.Minute}, "ai", nil, "")

	cfg := Config{
		ServiceName:    "ai",
		Secret:         secret,
		Enabled:        true,
		AllowedCallers: []string{"CLOUD", "administration"},
	}
	h := Middleware(cfg)(newHandler(t, true, ""))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(HeaderServiceAuth, tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestRequireServiceAuth_MissingHeader_401(t *testing.T) {
	cfg := Config{ServiceName: "ai", Secret: "s", Enabled: true}
	h := RequireServiceAuth(cfg)(newHandler(t, false, ""))

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestRequireServiceAuth_Disabled_PassesThrough(t *testing.T) {
	cfg := Config{ServiceName: "ai", Secret: "s", Enabled: false}
	h := RequireServiceAuth(cfg)(newHandler(t, false, ""))

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
}
