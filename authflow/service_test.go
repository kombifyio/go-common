package authflow

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/kombifyio/go-common/authsession"
	"github.com/kombifyio/go-common/oidcclient"
)

var (
	testSessionSecret = []byte("0123456789abcdef0123456789abcdef")
	testStateSecret   = []byte("fedcba9876543210fedcba9876543210")
)

type fakeExchanger struct {
	result       *oidcclient.CodeExchangeResult
	err          error
	seenCode     string
	seenRedirect string
	seenVerifier string
}

func (f *fakeExchanger) ExchangeCode(_ context.Context, _ *oidcclient.Provider, req oidcclient.CodeExchangeRequest) (*oidcclient.CodeExchangeResult, error) {
	f.seenCode = req.Code
	f.seenRedirect = req.RedirectURI
	f.seenVerifier = req.PKCEVerifier
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

func newProviderFixture(t *testing.T) (*oidcclient.Provider, *rsa.PrivateKey, *httptest.Server) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": "kid-1",
				"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
			}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	provider, err := oidcclient.NewProvider(oidcclient.ProviderConfig{
		ID:       "primary",
		Kind:     oidcclient.KindAuth0,
		Issuer:   server.URL,
		ClientID: "kombify-client",
	})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return provider, key, server
}

func newServiceFixture(t *testing.T, exchanger oidcclient.CodeExchanger) (*Service, *authsession.Manager) {
	t.Helper()
	provider, _, server := newProviderFixture(t)
	t.Cleanup(server.Close)
	registry := oidcclient.NewRegistry()
	registry.Add(provider)
	mgr, err := authsession.NewManager(authsession.Config{Audience: "frontend", Secret: testSessionSecret})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(Config{
		Providers:         registry,
		Sessions:          mgr,
		StateSecret:       testStateSecret,
		DefaultProviderID: "primary",
		DefaultTenantID:   "tenant-default",
		DefaultReturnTo:   "/dashboard",
		Exchanger:         exchanger,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, mgr
}

func signIDToken(t *testing.T, key *rsa.PrivateKey, issuer string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   issuer,
		"aud":   "kombify-client",
		"sub":   "user-123",
		"email": "user@example.com",
		"role":  "admin",
		"exp":   time.Now().Add(time.Minute).Unix(),
	})
	token.Header["kid"] = "kid-1"
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestProvidersHandler(t *testing.T) {
	svc, _ := newServiceFixture(t, &fakeExchanger{})
	req := httptest.NewRequest(http.MethodGet, "/providers", nil)
	rec := httptest.NewRecorder()
	svc.ProvidersHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	var body struct {
		Providers []struct {
			ID string `json:"id"`
		}
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Providers) != 1 || body.Providers[0].ID != "primary" {
		t.Fatalf("unexpected body: %+v", body)
	}
}

func TestLoginHandlerRedirects(t *testing.T) {
	svc, _ := newServiceFixture(t, &fakeExchanger{})
	req := httptest.NewRequest(http.MethodGet, "/login?return_to=%2Fjobs", nil)
	req.Host = "127.0.0.1:5260"
	rec := httptest.NewRecorder()
	svc.LoginHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	q := parsed.Query()
	if q.Get("client_id") != "kombify-client" {
		t.Fatalf("redirect client_id: %q", q.Get("client_id"))
	}
	if q.Get("redirect_uri") != "http://127.0.0.1:5260"+CallbackPath {
		t.Fatalf("redirect_uri: %q", q.Get("redirect_uri"))
	}
	if q.Get("state") == "" {
		t.Fatal("state missing")
	}
	stateClaims, err := svc.parseState(q.Get("state"))
	if err != nil {
		t.Fatalf("parse state: %v", err)
	}
	if stateClaims.PKCEVerifier == "" {
		t.Fatal("state missing PKCE verifier")
	}
	if strings.Contains(q.Get("state"), stateClaims.PKCEVerifier) {
		t.Fatal("state leaks raw PKCE verifier")
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("PKCE missing: %+v", q)
	}
}

func TestSanitizeReturnToRejectsExternalRedirectForms(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "absolute URL", raw: "https://evil.example/path", want: "/safe"},
		{name: "scheme relative URL", raw: "//evil.example/path", want: "/safe"},
		{name: "backslash authority", raw: "/\\evil.example/path", want: "/safe"},
		{name: "carriage return", raw: "/safe\rLocation: https://evil.example", want: "/safe"},
		{name: "relative path", raw: "jobs", want: "/safe"},
		{name: "local path with query and fragment", raw: "/jobs?tab=active#row-1", want: "/jobs?tab=active#row-1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeReturnTo(tt.raw, "/safe"); got != tt.want {
				t.Fatalf("sanitizeReturnTo(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestLogoutHandlerRejectsBackslashOpenRedirect(t *testing.T) {
	svc, _ := newServiceFixture(t, &fakeExchanger{})
	req := httptest.NewRequest(http.MethodGet, "/logout?next=%2F%5Cevil.example%2Fpath", nil)
	rec := httptest.NewRecorder()

	svc.LogoutHandler().ServeHTTP(rec, req)

	if got := rec.Header().Get("Location"); got != "/login" {
		t.Fatalf("redirect=%q, want local fallback", got)
	}
}

func TestCallbackHandlerSetsCookieAndRedirects(t *testing.T) {
	provider, key, server := newProviderFixture(t)
	defer server.Close()
	registry := oidcclient.NewRegistry()
	registry.Add(provider)
	mgr, err := authsession.NewManager(authsession.Config{Audience: "frontend", Secret: testSessionSecret})
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeExchanger{result: &oidcclient.CodeExchangeResult{IDToken: signIDToken(t, key, server.URL)}}
	svc, err := NewService(Config{
		Providers:         registry,
		Sessions:          mgr,
		StateSecret:       testStateSecret,
		DefaultProviderID: "primary",
		DefaultTenantID:   "tenant-default",
		DefaultReturnTo:   "/dashboard",
		Exchanger:         fake,
	})
	if err != nil {
		t.Fatal(err)
	}
	loginReq := httptest.NewRequest(http.MethodGet, "/login?tenant_id=tenant-42&return_to=%2Fagents", nil)
	loginReq.Host = "127.0.0.1:5260"
	loginRec := httptest.NewRecorder()
	svc.LoginHandler().ServeHTTP(loginRec, loginReq)
	state := mustStateFromRedirect(t, loginRec.Header().Get("Location"))
	callbackReq := httptest.NewRequest(http.MethodGet, "/callback?code=code-123&state="+url.QueryEscape(state), nil)
	callbackReq.Host = "127.0.0.1:5260"
	callbackRec := httptest.NewRecorder()
	svc.CallbackHandler().ServeHTTP(callbackRec, callbackReq)
	if callbackRec.Code != http.StatusFound {
		t.Fatalf("status=%d body=%q", callbackRec.Code, callbackRec.Body.String())
	}
	if got := callbackRec.Header().Get("Location"); got != "/agents" {
		t.Fatalf("redirect=%q", got)
	}
	if fake.seenCode != "code-123" {
		t.Fatalf("seen code=%q", fake.seenCode)
	}
	if fake.seenRedirect != "http://127.0.0.1:5260"+CallbackPath {
		t.Fatalf("redirect uri=%q", fake.seenRedirect)
	}
	if fake.seenVerifier == "" {
		t.Fatal("PKCE verifier not propagated")
	}
	cookies := callbackRec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != authsession.DefaultSessionCookieName {
		t.Fatalf("cookies=%+v", cookies)
	}
	claims, err := mgr.Verify(cookies[0].Value)
	if err != nil {
		t.Fatalf("verify session cookie: %v", err)
	}
	if claims.Subject != "user-123" || claims.TenantID != "tenant-42" || claims.Role != "admin" {
		t.Fatalf("claims=%+v", claims)
	}
}

func TestCallbackHandlerInvalidState(t *testing.T) {
	svc, _ := newServiceFixture(t, &fakeExchanger{})
	req := httptest.NewRequest(http.MethodGet, "/callback?code=c&state=garbage", nil)
	rec := httptest.NewRecorder()
	svc.CallbackHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "error=invalid_state") {
		t.Fatalf("location=%q", loc)
	}
}

func TestLogoutHandlerClearsCookieAndRedirects(t *testing.T) {
	svc, _ := newServiceFixture(t, &fakeExchanger{})
	req := httptest.NewRequest(http.MethodGet, "/logout?next=%2Flogin%3Flogged_out%3D1", nil)
	rec := httptest.NewRecorder()
	svc.LogoutHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/login?logged_out=1" {
		t.Fatalf("redirect=%q", got)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%+v", cookies)
	}
	if cookies[0].Name != authsession.DefaultSessionCookieName || cookies[0].MaxAge != -1 {
		t.Fatalf("logout cookie=%+v", cookies[0])
	}
}

func TestNewServiceValidatesConfig(t *testing.T) {
	mgr, _ := authsession.NewManager(authsession.Config{Audience: "frontend", Secret: testSessionSecret})
	registry := oidcclient.NewRegistry()
	if _, err := NewService(Config{Providers: registry, Sessions: mgr, StateSecret: testStateSecret}); err == nil {
		t.Fatal("expected error: empty registry")
	}
	provider, _, server := newProviderFixture(t)
	defer server.Close()
	registry.Add(provider)
	if _, err := NewService(Config{Providers: registry, Sessions: nil, StateSecret: testStateSecret}); err == nil {
		t.Fatal("expected error: missing sessions")
	}
	if _, err := NewService(Config{Providers: registry, Sessions: mgr, StateSecret: []byte("short")}); err == nil {
		t.Fatal("expected error: short state secret")
	}
}

func TestTenantResolverInvoked(t *testing.T) {
	provider, key, server := newProviderFixture(t)
	defer server.Close()
	registry := oidcclient.NewRegistry()
	registry.Add(provider)
	mgr, _ := authsession.NewManager(authsession.Config{Audience: "frontend", Secret: testSessionSecret})
	fake := &fakeExchanger{result: &oidcclient.CodeExchangeResult{IDToken: signIDToken(t, key, server.URL)}}

	resolverCalls := 0
	svc, err := NewService(Config{
		Providers:         registry,
		Sessions:          mgr,
		StateSecret:       testStateSecret,
		DefaultProviderID: "primary",
		DefaultTenantID:   "tenant-default",
		Exchanger:         fake,
		TenantResolver: func(ctx context.Context, c *oidcclient.Claims, providerID, requested string) (string, error) {
			resolverCalls++
			return "tenant-from-resolver", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	loginReq := httptest.NewRequest(http.MethodGet, "/login", nil)
	loginReq.Host = "127.0.0.1:5260"
	loginRec := httptest.NewRecorder()
	svc.LoginHandler().ServeHTTP(loginRec, loginReq)
	state := mustStateFromRedirect(t, loginRec.Header().Get("Location"))
	cbReq := httptest.NewRequest(http.MethodGet, "/callback?code=c&state="+url.QueryEscape(state), nil)
	cbReq.Host = "127.0.0.1:5260"
	cbRec := httptest.NewRecorder()
	svc.CallbackHandler().ServeHTTP(cbRec, cbReq)
	if resolverCalls != 1 {
		t.Fatalf("resolver called %d times", resolverCalls)
	}
	cookies := cbRec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%+v", cookies)
	}
	claims, err := mgr.Verify(cookies[0].Value)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.TenantID != "tenant-from-resolver" {
		t.Fatalf("tenant=%q", claims.TenantID)
	}
}

func mustStateFromRedirect(t *testing.T, location string) string {
	t.Helper()
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if strings.TrimSpace(state) == "" {
		t.Fatal("state missing")
	}
	return state
}
