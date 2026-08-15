package edgeauth_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kombifyio/go-common/edgeauth"
	"github.com/kombifyio/go-common/identity"
)

// makeRequest builds an http.Request with the given headers.
func makeRequest(headers map[string]string) *http.Request {
	return makeRequestWithMethod(http.MethodGet, "/", headers)
}

func makeRequestWithPath(path string, headers map[string]string) *http.Request {
	return makeRequestWithMethod(http.MethodGet, path, headers)
}

func makeRequestWithMethod(method, path string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func runMiddleware(cfg edgeauth.Config, r *http.Request) (*httptest.ResponseRecorder, *http.Request) {
	var captured *http.Request
	handler := edgeauth.Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		captured = req
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w, captured
}

func signEdgeTestRequest(r *http.Request, secret, signedPath, timestamp, nonce string) {
	signEdgeTestRequestWithMethodAndKeyID(r, secret, r.Method, signedPath, "primary", timestamp, nonce)
}

func signEdgeTestRequestWithKeyID(r *http.Request, secret, signedPath, keyID, timestamp, nonce string) {
	signEdgeTestRequestWithMethodAndKeyID(r, secret, r.Method, signedPath, keyID, timestamp, nonce)
}

func signEdgeTestRequestWithMethodAndKeyID(r *http.Request, secret, method, signedPath, keyID, timestamp, nonce string) {
	r.Header.Set("X-Kombify-Edge-Key-ID", keyID)
	payload := strings.Join([]string{
		"v1",
		keyID,
		strings.ToUpper(method),
		signedPath,
		r.Header.Get("X-Kombify-Edge-Auth"),
		r.Header.Get("X-Kombify-Edge-Service"),
		r.Header.Get("X-Kombify-Public-Prefix"),
		r.Header.Get("X-User-ID"),
		r.Header.Get("X-Org-ID"),
		r.Header.Get("X-User-Email"),
		r.Header.Get("X-User-Tier"),
		r.Header.Get("X-User-Roles"),
		r.Header.Get("X-User-Scope"),
		timestamp,
		nonce,
	}, "\n")
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	r.Header.Set("X-Kombify-Edge-Signature", "v1="+base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	r.Header.Set("X-Kombify-Edge-Timestamp", timestamp)
	r.Header.Set("X-Kombify-Edge-Nonce", nonce)
	r.Header.Set("X-Kombify-Edge-Signed-Path", signedPath)
}

func signedConfig() edgeauth.Config {
	return edgeauth.Config{
		Enabled:          true,
		RequireEdgeAuth:  true,
		RequireSignature: true,
		EdgeAuthSecret:   "test-edge-secret",
	}
}

// ── Middleware disabled ────────────────────────────────────────────────────────

func TestMiddleware_Disabled_PassesThrough(t *testing.T) {
	cfg := edgeauth.Config{Enabled: false}
	r := makeRequest(nil)
	w, captured := runMiddleware(cfg, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if captured == nil {
		t.Fatal("handler was not called")
	}
	id := identity.FromContext(captured.Context())
	if id != nil && id.UserID != "" {
		t.Error("expected no identity in context when middleware is disabled")
	}
}

// ── RequireEdgeAuth = false (permissive mode) ──────────────────────────────────

func TestMiddleware_NoEdgeAuthHeader_Permissive_PassesThrough(t *testing.T) {
	cfg := edgeauth.Config{Enabled: true, RequireEdgeAuth: false}
	r := makeRequest(nil) // no x-kombify-edge-auth header
	w, captured := runMiddleware(cfg, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if captured == nil {
		t.Fatal("handler was not called")
	}
	// No identity should be injected without the edge-auth header.
	id := identity.FromContext(captured.Context())
	if id != nil && id.UserID != "" {
		t.Error("unexpected identity injected without edge-auth header")
	}
}

// ── RequireEdgeAuth = true (strict mode) ──────────────────────────────────────

func TestMiddleware_NoEdgeAuthHeader_Strict_Returns401(t *testing.T) {
	cfg := edgeauth.Config{Enabled: true, RequireEdgeAuth: true}
	r := makeRequest(nil)
	w, _ := runMiddleware(cfg, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	if got := w.Header().Get("WWW-Authenticate"); got == "" {
		t.Error("expected WWW-Authenticate header on 401")
	}
}

func TestMiddleware_WrongEdgeAuthValue_Strict_Returns401(t *testing.T) {
	cfg := edgeauth.Config{Enabled: true, RequireEdgeAuth: true}
	r := makeRequest(map[string]string{"X-Kombify-Edge-Auth": "kong-jwt"}) // wrong value
	w, _ := runMiddleware(cfg, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// ── Valid edge-auth header ─────────────────────────────────────────────────────

func TestMiddleware_ValidEdgeAuth_ExtractsIdentity(t *testing.T) {
	cfg := signedConfig()
	r := makeRequest(map[string]string{
		"X-Kombify-Edge-Auth": "auth0-jwt",
		"X-User-ID":           "auth0|user-123",
		"X-Org-ID":            "org_abc",
		"X-User-Email":        "user@example.com",
		"X-User-Roles":        "admin, member",
		"X-Request-ID":        "req-xyz",
	})
	signEdgeTestRequest(r, "test-edge-secret", "/", strconvNow(), "nonce-user-123")
	w, captured := runMiddleware(cfg, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if captured == nil {
		t.Fatal("handler was not called")
	}

	id := identity.FromContext(captured.Context())
	if id == nil {
		t.Fatal("expected identity in context, got nil")
	}
	if id.UserID != "auth0|user-123" {
		t.Errorf("UserID: got %q, want %q", id.UserID, "auth0|user-123")
	}
	if id.OrgID != "org_abc" {
		t.Errorf("OrgID: got %q, want %q", id.OrgID, "org_abc")
	}
	if id.Email != "user@example.com" {
		t.Errorf("Email: got %q, want %q", id.Email, "user@example.com")
	}
	if len(id.Roles) != 2 || id.Roles[0] != "admin" || id.Roles[1] != "member" {
		t.Errorf("Roles: got %v, want [admin member]", id.Roles)
	}
}

func TestMiddleware_ValidEdgeAuth_CaseInsensitive(t *testing.T) {
	cfg := signedConfig()
	r := makeRequest(map[string]string{
		"X-Kombify-Edge-Auth": "AUTH0-JWT", // uppercase
		"X-User-ID":           "auth0|user-456",
	})
	signEdgeTestRequest(r, "test-edge-secret", "/", strconvNow(), "nonce-user-456")
	w, captured := runMiddleware(cfg, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	id := identity.FromContext(captured.Context())
	if id == nil || id.UserID != "auth0|user-456" {
		t.Errorf("expected identity with user-456, got %v", id)
	}
}

// ── Anonymous edge requests ───────────────────────────────────────────────────

func TestMiddleware_NoUserID_StoresEmptyIdentity(t *testing.T) {
	// Edge-auth present but no user headers (anonymous request somehow slipped through).
	cfg := signedConfig()
	cfg.RequireEdgeAuth = false
	r := makeRequest(map[string]string{
		"X-Kombify-Edge-Auth": "auth0-jwt",
		// intentionally no X-User-ID
	})
	signEdgeTestRequest(r, "test-edge-secret", "/", strconvNow(), "nonce-no-user")
	_, captured := runMiddleware(cfg, r)

	// identity.Identity is stored but with empty UserID.
	id := identity.FromContext(captured.Context())
	if id != nil && id.UserID != "" {
		t.Error("unexpected non-empty UserID")
	}
}

// ── Tier extraction ───────────────────────────────────────────────────────────

func TestMiddleware_ValidEdgeAuth_ExtractsTier(t *testing.T) {
	cfg := signedConfig()
	r := makeRequest(map[string]string{
		"X-Kombify-Edge-Auth": "auth0-jwt",
		"X-User-ID":           "auth0|tier-user",
		"X-User-Tier":         "PRO",
	})
	signEdgeTestRequest(r, "test-edge-secret", "/", strconvNow(), "nonce-tier")
	w, captured := runMiddleware(cfg, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	id := identity.FromContext(captured.Context())
	if id == nil {
		t.Fatal("expected identity in context, got nil")
	}
	if id.Tier != "PRO" {
		t.Errorf("Tier: got %q, want %q", id.Tier, "PRO")
	}
}

func TestMiddleware_ValidEdgeAuth_TierEmptyWhenAbsent(t *testing.T) {
	cfg := signedConfig()
	r := makeRequest(map[string]string{
		"X-Kombify-Edge-Auth": "auth0-jwt",
		"X-User-ID":           "auth0|no-tier",
		// intentionally no X-User-Tier
	})
	signEdgeTestRequest(r, "test-edge-secret", "/", strconvNow(), "nonce-no-tier")
	_, captured := runMiddleware(cfg, r)

	id := identity.FromContext(captured.Context())
	if id == nil {
		t.Fatal("expected identity in context, got nil")
	}
	if id.Tier != "" {
		t.Errorf("Tier: got %q, want empty string", id.Tier)
	}
}

// ── Signed edge-origin trust ─────────────────────────────────────────────────

func TestMiddleware_ValidSignedEdgeAuth_ExtractsIdentity(t *testing.T) {
	cfg := edgeauth.Config{
		Enabled:          true,
		RequireEdgeAuth:  true,
		RequireSignature: true,
		EdgeAuthSecret:   "test-edge-secret",
	}
	r := makeRequestWithPath("/v1/admin/metrics?debug=1", map[string]string{
		"X-Kombify-Edge-Auth": "auth0-jwt",
		"X-User-ID":           "auth0|signed-user",
		"X-Org-ID":            "org_signed",
		"X-User-Email":        "signed@example.com",
		"X-User-Tier":         "PRO",
		"X-User-Roles":        "admin",
		"X-User-Scope":        "openid profile",
	})
	signEdgeTestRequest(r, "test-edge-secret", "/v1/admin/metrics?debug=1", strconvNow(), "nonce-1")

	w, captured := runMiddleware(cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	id := identity.FromContext(captured.Context())
	if id == nil || id.UserID != "auth0|signed-user" || id.OrgID != "org_signed" {
		t.Fatalf("unexpected identity: %#v", id)
	}
}

func TestMiddleware_SignedEdgeAuth_TamperedHeader_Returns401(t *testing.T) {
	cfg := edgeauth.Config{
		Enabled:          true,
		RequireEdgeAuth:  true,
		RequireSignature: true,
		EdgeAuthSecret:   "test-edge-secret",
	}
	r := makeRequestWithPath("/v1/admin/metrics", map[string]string{
		"X-Kombify-Edge-Auth": "auth0-jwt",
		"X-User-ID":           "auth0|signed-user",
		"X-User-Tier":         "FREE",
	})
	signEdgeTestRequest(r, "test-edge-secret", "/v1/admin/metrics", strconvNow(), "nonce-2")
	r.Header.Set("X-User-Tier", "ENTERPRISE")

	w, _ := runMiddleware(cfg, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestMiddleware_SignedEdgeAuth_AcceptsNextSecret(t *testing.T) {
	cfg := edgeauth.Config{
		Enabled:            true,
		RequireEdgeAuth:    true,
		RequireSignature:   true,
		EdgeAuthSecret:     "old-secret",
		EdgeAuthNextSecret: "next-secret",
	}
	r := makeRequestWithPath("/v1/admin/metrics", map[string]string{
		"X-Kombify-Edge-Auth": "auth0-jwt",
		"X-User-ID":           "auth0|rotating",
	})
	signEdgeTestRequestWithKeyID(r, "next-secret", "/v1/admin/metrics", "next", strconvNow(), "nonce-3")

	w, _ := runMiddleware(cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMiddleware_SignedEdgeAuth_MissingSignatureWithSecret_Returns401(t *testing.T) {
	cfg := edgeauth.Config{
		Enabled:         true,
		RequireEdgeAuth: true,
		EdgeAuthSecret:  "test-edge-secret",
	}
	r := makeRequestWithPath("/v1/admin/metrics", map[string]string{
		"X-Kombify-Edge-Auth": "auth0-jwt",
		"X-User-ID":           "auth0|missing-signature",
	})

	w, _ := runMiddleware(cfg, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestMiddleware_SignedEdgeAuth_ExpiredTimestamp_Returns401(t *testing.T) {
	cfg := edgeauth.Config{
		Enabled:          true,
		RequireEdgeAuth:  true,
		RequireSignature: true,
		EdgeAuthSecret:   "test-edge-secret",
		SignatureWindow:  time.Minute,
	}
	r := makeRequestWithPath("/v1/admin/metrics", map[string]string{
		"X-Kombify-Edge-Auth": "auth0-jwt",
		"X-User-ID":           "auth0|expired",
	})
	expired := strconv.FormatInt(time.Now().Add(-2*time.Minute).Unix(), 10)
	signEdgeTestRequest(r, "test-edge-secret", "/v1/admin/metrics", expired, "nonce-expired")

	w, _ := runMiddleware(cfg, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestMiddleware_SignedEdgeAuth_MethodMismatch_Returns401(t *testing.T) {
	cfg := signedConfig()
	r := makeRequestWithMethod(http.MethodPost, "/v1/admin/metrics", map[string]string{
		"X-Kombify-Edge-Auth": "auth0-jwt",
		"X-User-ID":           "auth0|method-mismatch",
	})
	signEdgeTestRequestWithMethodAndKeyID(r, "test-edge-secret", http.MethodGet, "/v1/admin/metrics", "primary", strconvNow(), "nonce-method")

	w, _ := runMiddleware(cfg, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestMiddleware_SignedEdgeAuth_PathMismatch_Returns401(t *testing.T) {
	cfg := signedConfig()
	r := makeRequestWithPath("/v1/admin/metrics", map[string]string{
		"X-Kombify-Edge-Auth": "auth0-jwt",
		"X-User-ID":           "auth0|path-mismatch",
	})
	signEdgeTestRequest(r, "test-edge-secret", "/v1/admin/users", strconvNow(), "nonce-path")

	w, _ := runMiddleware(cfg, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestMiddleware_SignedEdgeAuth_UnsignedSpoofedHeaders_Returns401(t *testing.T) {
	cfg := edgeauth.Config{Enabled: true, RequireEdgeAuth: false}
	r := makeRequest(map[string]string{
		"X-User-ID":    "auth0|spoofed",
		"X-User-Roles": "admin",
	})

	w, _ := runMiddleware(cfg, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestMiddleware_SignedEdgeAuth_AcceptsSignedAPIKeyIdentity(t *testing.T) {
	cfg := signedConfig()
	r := makeRequestWithPath("/api/v1/simulations", map[string]string{
		"X-Kombify-Edge-Auth": "api-key",
		"X-User-ID":           "service:internal",
		"X-User-Tier":         "INTERNAL",
		"X-User-Roles":        "service,internal",
		"X-User-Scope":        "api:key",
	})
	signEdgeTestRequest(r, "test-edge-secret", "/api/v1/simulations", strconvNow(), "nonce-api-key")

	w, captured := runMiddleware(cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	id := identity.FromContext(captured.Context())
	if id == nil || id.UserID != "service:internal" || id.Tier != "INTERNAL" {
		t.Fatalf("unexpected identity: %#v", id)
	}
}

func strconvNow() string {
	return strconv.FormatInt(time.Now().Unix(), 10)
}

// ── IsEdgeAuthenticated helper ────────────────────────────────────────────────

func TestIsEdgeAuthenticated(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected bool
	}{
		{"valid lowercase", "auth0-jwt", true},
		{"valid uppercase", "AUTH0-JWT", true},
		{"valid mixed case", "Auth0-Jwt", true},
		{"valid api key", "api-key", true},
		{"wrong value", "kong-jwt", false},
		{"empty", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				r.Header.Set("X-Kombify-Edge-Auth", tc.header)
			}
			got := edgeauth.IsEdgeAuthenticated(r)
			if got != tc.expected {
				t.Errorf("IsEdgeAuthenticated(%q): got %v, want %v", tc.header, got, tc.expected)
			}
		})
	}
}

// ── v2 signature: entitlements + knowledge-tier binding (W0.1) ────────────────

// signEdgeTestRequestV2 signs a request with the v2 edge signature, which binds
// X-Kombify-Entitlements and X-Kombify-Knowledge-Tier in addition to the v1 fields.
func signEdgeTestRequestV2(r *http.Request, secret, signedPath, timestamp, nonce string) {
	keyID := "primary"
	r.Header.Set("X-Kombify-Edge-Key-ID", keyID)
	payload := strings.Join([]string{
		"v2",
		keyID,
		strings.ToUpper(r.Method),
		signedPath,
		r.Header.Get("X-Kombify-Edge-Auth"),
		r.Header.Get("X-Kombify-Edge-Service"),
		r.Header.Get("X-Kombify-Public-Prefix"),
		r.Header.Get("X-User-ID"),
		r.Header.Get("X-Org-ID"),
		r.Header.Get("X-User-Email"),
		r.Header.Get("X-User-Tier"),
		r.Header.Get("X-User-Roles"),
		r.Header.Get("X-User-Scope"),
		r.Header.Get("X-Kombify-Entitlements"),
		r.Header.Get("X-Kombify-Knowledge-Tier"),
		timestamp,
		nonce,
	}, "\n")
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	r.Header.Set("X-Kombify-Edge-Signature", "v2="+base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	r.Header.Set("X-Kombify-Edge-Timestamp", timestamp)
	r.Header.Set("X-Kombify-Edge-Nonce", nonce)
	r.Header.Set("X-Kombify-Edge-Signed-Path", signedPath)
}

func TestMiddleware_V2Signature_Valid_PassesThrough(t *testing.T) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	r := makeRequest(map[string]string{
		"X-Kombify-Edge-Auth":      "auth0-jwt",
		"X-User-ID":                "auth0|abc",
		"X-Kombify-Entitlements":   "ai.tier.premium,mcp.knowledge.codebase.search",
		"X-Kombify-Knowledge-Tier": "business",
	})
	signEdgeTestRequestV2(r, "test-edge-secret", "/", ts, "nonce-v2-ok")
	w, captured := runMiddleware(signedConfig(), r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid v2 signature, got %d (%s)", w.Code, w.Body.String())
	}
	if captured == nil {
		t.Fatal("handler was not called for valid v2 signature")
	}
}

func TestMiddleware_V2Signature_TamperedEntitlements_Rejected(t *testing.T) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	r := makeRequest(map[string]string{
		"X-Kombify-Edge-Auth":      "auth0-jwt",
		"X-User-ID":                "auth0|abc",
		"X-Kombify-Entitlements":   "ai.tier.free",
		"X-Kombify-Knowledge-Tier": "public",
	})
	signEdgeTestRequestV2(r, "test-edge-secret", "/", ts, "nonce-v2-tamper-ent")
	// Attacker escalates entitlements after the edge signed the request.
	r.Header.Set("X-Kombify-Entitlements", "ai.tier.premium")
	w, _ := runMiddleware(signedConfig(), r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for tampered entitlements, got %d", w.Code)
	}
}

func TestMiddleware_V2Signature_TamperedKnowledgeTier_Rejected(t *testing.T) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	r := makeRequest(map[string]string{
		"X-Kombify-Edge-Auth":      "auth0-jwt",
		"X-User-ID":                "auth0|abc",
		"X-Kombify-Entitlements":   "ai.tier.free",
		"X-Kombify-Knowledge-Tier": "public",
	})
	signEdgeTestRequestV2(r, "test-edge-secret", "/", ts, "nonce-v2-tamper-kt")
	// Attacker escalates knowledge tier after the edge signed the request.
	r.Header.Set("X-Kombify-Knowledge-Tier", "business")
	w, _ := runMiddleware(signedConfig(), r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for tampered knowledge tier, got %d", w.Code)
	}
}

func TestMiddleware_UnsignedEntitlementsHeader_Rejected(t *testing.T) {
	// Entitlements header present but no edge-auth signature at all must be rejected.
	r := makeRequest(map[string]string{
		"X-Kombify-Entitlements": "ai.tier.premium",
	})
	w, _ := runMiddleware(signedConfig(), r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unsigned entitlements header, got %d", w.Code)
	}
}

// v1 signatures must keep working during the staged rollout (backward compatibility).
func TestMiddleware_V1Signature_StillValid_AfterV2Support(t *testing.T) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	r := makeRequest(map[string]string{
		"X-Kombify-Edge-Auth": "auth0-jwt",
		"X-User-ID":           "auth0|abc",
	})
	signEdgeTestRequest(r, "test-edge-secret", "/", ts, "nonce-v1-compat")
	w, captured := runMiddleware(signedConfig(), r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid v1 signature, got %d (%s)", w.Code, w.Body.String())
	}
	if captured == nil {
		t.Fatal("handler was not called for valid v1 signature")
	}
}
