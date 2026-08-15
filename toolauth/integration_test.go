package toolauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockAPI is a configurable mock server that implements all Cloud API endpoints
// used by the toolauth client. It tracks call counts and allows per-endpoint
// behavior overrides.
type mockAPI struct {
	mu sync.Mutex

	// verifyHandler handles POST /api/v1/tools/auth/verify.
	verifyHandler func(w http.ResponseWriter, r *http.Request)
	// refreshHandler handles POST /api/v1/tools/auth/refresh.
	refreshHandler func(w http.ResponseWriter, r *http.Request)
	// deviceCodeHandler handles POST /api/v1/tools/auth/device-code.
	deviceCodeHandler func(w http.ResponseWriter, r *http.Request)
	// deviceCodePollHandler handles POST /api/v1/tools/auth/device-code/poll.
	deviceCodePollHandler func(w http.ResponseWriter, r *http.Request)
	// entitlementsHandler handles GET /api/v1/tools/entitlements.
	entitlementsHandler func(w http.ResponseWriter, r *http.Request)
	// usageHandler handles POST /api/v1/tools/usage.
	usageHandler func(w http.ResponseWriter, r *http.Request)

	verifyCalls      atomic.Int32
	refreshCalls     atomic.Int32
	deviceCodeCalls  atomic.Int32
	pollCalls        atomic.Int32
	entitlementCalls atomic.Int32
	usageCalls       atomic.Int32
}

func (m *mockAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	handler := m.routeHandler(r)
	m.mu.Unlock()

	if handler == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	handler(w, r)
}

func (m *mockAPI) routeHandler(r *http.Request) func(http.ResponseWriter, *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/tools/auth/verify":
		m.verifyCalls.Add(1)
		return m.verifyHandler
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/tools/auth/refresh":
		m.refreshCalls.Add(1)
		return m.refreshHandler
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/tools/auth/device-code":
		m.deviceCodeCalls.Add(1)
		return m.deviceCodeHandler
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/tools/auth/device-code/poll":
		m.pollCalls.Add(1)
		return m.deviceCodePollHandler
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/tools/entitlements":
		m.entitlementCalls.Add(1)
		return m.entitlementsHandler
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/tools/usage":
		m.usageCalls.Add(1)
		return m.usageHandler
	default:
		return nil
	}
}

// setDeviceCodePollHandler replaces the poll handler under lock.
func (m *mockAPI) setDeviceCodePollHandler(h func(http.ResponseWriter, *http.Request)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deviceCodePollHandler = h
}

// integrationEntitlements returns a standard entitlement set used across integration tests.
func integrationEntitlements() *Entitlements {
	return &Entitlements{
		Tool: "speechkit",
		Features: map[string]any{
			"whisper_local": true,
			"max_duration":  float64(600),
			"cloud_export":  false,
		},
	}
}

// integrationAuthResponse builds an authResponse with a token valid for 1 hour.
func integrationAuthResponse() authResponse {
	return authResponse{
		Token: TokenPair{
			AccessToken:  "int-access-token",
			RefreshToken: "int-refresh-token",
			ExpiresAt:    time.Now().Add(1 * time.Hour),
			UserID:       "usr-integration",
		},
		Entitlements: integrationEntitlements(),
	}
}

// writeJSON is a helper that marshals v as JSON and writes it to w.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// TestIntegration_FullAPIKeyFlow tests the complete lifecycle using API key authentication:
// authenticate, read cached token, read cached entitlements, check features,
// buffer and flush usage, and logout.
func TestIntegration_FullAPIKeyFlow(t *testing.T) {
	var receivedUsage usagePayload

	mock := &mockAPI{
		verifyHandler: func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("X-API-Key"); got != "int-api-key" {
				t.Errorf("X-API-Key = %q, want %q", got, "int-api-key")
			}
			var req authVerifyRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode verify request: %v", err)
			}
			if req.Tool != "speechkit" {
				t.Errorf("Tool = %q, want %q", req.Tool, "speechkit")
			}
			writeJSON(w, integrationAuthResponse())
		},
		entitlementsHandler: func(w http.ResponseWriter, r *http.Request) {
			t.Error("entitlements endpoint should not be called when cache is warm from auth")
			http.Error(w, "unexpected", http.StatusInternalServerError)
		},
		usageHandler: func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Authorization"); got != "Bearer int-access-token" {
				t.Errorf("Authorization = %q, want %q", got, "Bearer int-access-token")
			}
			if err := json.NewDecoder(r.Body).Decode(&receivedUsage); err != nil {
				t.Errorf("decode usage payload: %v", err)
			}
			w.WriteHeader(http.StatusOK)
		},
	}

	srv := httptest.NewServer(mock)
	defer srv.Close()

	store := newMemStore()
	ctx := context.Background()

	// Step 1: Create client.
	c, err := New(Config{
		BaseURL:     srv.URL,
		ToolName:    "speechkit",
		ToolVersion: "0.1.0",
		TokenStore:  store,
		HTTPClient:  &http.Client{Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if c.IsAuthenticated() {
		t.Fatal("expected new client to not be authenticated")
	}

	// Step 2: Authenticate with API key.
	result, err := c.AuthenticateWithAPIKey(ctx, "int-api-key")
	if err != nil {
		t.Fatalf("AuthenticateWithAPIKey() error: %v", err)
	}
	if result.Token.AccessToken != "int-access-token" {
		t.Errorf("AccessToken = %q, want %q", result.Token.AccessToken, "int-access-token")
	}
	if result.Token.UserID != "usr-integration" {
		t.Errorf("UserID = %q, want %q", result.Token.UserID, "usr-integration")
	}
	if result.Entitlements == nil {
		t.Fatal("Entitlements is nil after auth")
	}

	// Step 3: GetAccessToken returns cached token (no HTTP call).
	token, err := c.GetAccessToken(ctx)
	if err != nil {
		t.Fatalf("GetAccessToken() error: %v", err)
	}
	if token != "int-access-token" {
		t.Errorf("GetAccessToken() = %q, want %q", token, "int-access-token")
	}

	// Step 4: GetEntitlements returns cached from auth (no HTTP call to entitlements).
	ent, err := c.GetEntitlements(ctx)
	if err != nil {
		t.Fatalf("GetEntitlements() error: %v", err)
	}
	if ent.Tool != "speechkit" {
		t.Errorf("Entitlements.Tool = %q, want %q", ent.Tool, "speechkit")
	}
	if mock.entitlementCalls.Load() != 0 {
		t.Errorf("entitlements API called %d times, want 0 (should be cached from auth)", mock.entitlementCalls.Load())
	}

	// Step 5: HasFeature checks specific features.
	has, err := c.HasFeature(ctx, "whisper_local")
	if err != nil {
		t.Fatalf("HasFeature(whisper_local) error: %v", err)
	}
	if !has {
		t.Error("HasFeature(whisper_local) = false, want true")
	}

	has, err = c.HasFeature(ctx, "cloud_export")
	if err != nil {
		t.Fatalf("HasFeature(cloud_export) error: %v", err)
	}
	if has {
		t.Error("HasFeature(cloud_export) = true, want false")
	}

	has, err = c.HasFeature(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("HasFeature(nonexistent) error: %v", err)
	}
	if has {
		t.Error("HasFeature(nonexistent) = true, want false")
	}

	// Step 6: ReportUsage buffers events.
	now := time.Now()
	err = c.ReportUsage(ctx,
		UsageEvent{Metric: "transcription_minutes", Value: 12.5, At: now},
		UsageEvent{Metric: "api_calls", Value: 3, At: now},
	)
	if err != nil {
		t.Fatalf("ReportUsage() error: %v", err)
	}

	// Step 7: Flush usage and verify events sent to API.
	if err := c.flushUsage(ctx); err != nil {
		t.Fatalf("flushUsage() error: %v", err)
	}
	if mock.usageCalls.Load() != 1 {
		t.Errorf("usage API called %d times, want 1", mock.usageCalls.Load())
	}
	if receivedUsage.Tool != "speechkit" {
		t.Errorf("usage payload Tool = %q, want %q", receivedUsage.Tool, "speechkit")
	}
	if len(receivedUsage.Events) != 2 {
		t.Errorf("usage payload events = %d, want 2", len(receivedUsage.Events))
	}

	// Buffer should be empty after successful flush.
	c.usageMu.Lock()
	bufLen := len(c.usageBuf)
	c.usageMu.Unlock()
	if bufLen != 0 {
		t.Errorf("usage buffer after flush = %d, want 0", bufLen)
	}

	// Step 8: Logout clears everything.
	if err := c.Logout(ctx); err != nil {
		t.Fatalf("Logout() error: %v", err)
	}
	if c.IsAuthenticated() {
		t.Error("expected IsAuthenticated() == false after Logout")
	}

	// Token cleared from store.
	stored, err := store.Load("speechkit")
	if err != nil {
		t.Fatalf("store.Load() error: %v", err)
	}
	if stored != nil {
		t.Error("expected stored token to be nil after Logout")
	}

	// GetAccessToken fails after logout.
	_, err = c.GetAccessToken(ctx)
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("GetAccessToken() after logout: error = %v, want %v", err, ErrNotAuthenticated)
	}

	// Verify API was called exactly once for auth.
	if mock.verifyCalls.Load() != 1 {
		t.Errorf("verify API called %d times, want 1", mock.verifyCalls.Load())
	}
}

// TestIntegration_FullDeviceCodeFlow tests the device code flow end-to-end:
// start flow, poll pending, poll success, then verify tokens and entitlements work.
func TestIntegration_FullDeviceCodeFlow(t *testing.T) {
	mock := &mockAPI{
		deviceCodeHandler: func(w http.ResponseWriter, r *http.Request) {
			var req deviceCodeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode device code request: %v", err)
			}
			if req.Tool != "speechkit" {
				t.Errorf("Tool = %q, want %q", req.Tool, "speechkit")
			}
			writeJSON(w, DeviceCodeResponse{
				DeviceCode:      "int-device-code",
				UserCode:        "INTG-5678",
				VerificationURI: "https://kombify.io/device",
				ExpiresIn:       300,
				Interval:        5,
			})
		},
		deviceCodePollHandler: func(w http.ResponseWriter, r *http.Request) {
			// First poll: authorization pending.
			w.WriteHeader(http.StatusAccepted)
		},
		entitlementsHandler: func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, integrationEntitlements())
		},
	}

	srv := httptest.NewServer(mock)
	defer srv.Close()

	store := newMemStore()
	ctx := context.Background()

	c, err := New(Config{
		BaseURL:     srv.URL,
		ToolName:    "speechkit",
		ToolVersion: "0.1.0",
		TokenStore:  store,
		HTTPClient:  &http.Client{Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Step 1: Start device code flow.
	dcResp, err := c.StartDeviceCodeFlow(ctx)
	if err != nil {
		t.Fatalf("StartDeviceCodeFlow() error: %v", err)
	}
	if dcResp.DeviceCode != "int-device-code" {
		t.Errorf("DeviceCode = %q, want %q", dcResp.DeviceCode, "int-device-code")
	}
	if dcResp.UserCode != "INTG-5678" {
		t.Errorf("UserCode = %q, want %q", dcResp.UserCode, "INTG-5678")
	}
	if dcResp.VerificationURI != "https://kombify.io/device" {
		t.Errorf("VerificationURI = %q, want %q", dcResp.VerificationURI, "https://kombify.io/device")
	}

	// Step 2: First poll returns ErrAuthorizationPending.
	_, err = c.PollDeviceCode(ctx, dcResp.DeviceCode)
	if !errors.Is(err, ErrAuthorizationPending) {
		t.Fatalf("first PollDeviceCode() error = %v, want %v", err, ErrAuthorizationPending)
	}
	if mock.pollCalls.Load() != 1 {
		t.Errorf("poll calls = %d, want 1", mock.pollCalls.Load())
	}

	// Step 3: Swap handler to simulate user completing authorization.
	mock.setDeviceCodePollHandler(func(w http.ResponseWriter, r *http.Request) {
		var req deviceCodePollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode poll request: %v", err)
		}
		if req.DeviceCode != "int-device-code" {
			t.Errorf("DeviceCode = %q, want %q", req.DeviceCode, "int-device-code")
		}
		w.WriteHeader(http.StatusOK)
		writeJSON(w, integrationAuthResponse())
	})

	// Step 4: Second poll returns success.
	result, err := c.PollDeviceCode(ctx, dcResp.DeviceCode)
	if err != nil {
		t.Fatalf("second PollDeviceCode() error: %v", err)
	}
	if result.Token.AccessToken != "int-access-token" {
		t.Errorf("AccessToken = %q, want %q", result.Token.AccessToken, "int-access-token")
	}
	if result.Token.UserID != "usr-integration" {
		t.Errorf("UserID = %q, want %q", result.Token.UserID, "usr-integration")
	}
	if result.Entitlements == nil {
		t.Fatal("Entitlements is nil after successful poll")
	}

	// Step 5: GetAccessToken works.
	token, err := c.GetAccessToken(ctx)
	if err != nil {
		t.Fatalf("GetAccessToken() error: %v", err)
	}
	if token != "int-access-token" {
		t.Errorf("GetAccessToken() = %q, want %q", token, "int-access-token")
	}

	// Step 6: GetEntitlements works (cached from poll auth response).
	ent, err := c.GetEntitlements(ctx)
	if err != nil {
		t.Fatalf("GetEntitlements() error: %v", err)
	}
	if ent.Tool != "speechkit" {
		t.Errorf("Entitlements.Tool = %q, want %q", ent.Tool, "speechkit")
	}
	// Should not have called the entitlements endpoint since we got them from poll.
	if mock.entitlementCalls.Load() != 0 {
		t.Errorf("entitlements API called %d times, want 0 (should be cached from poll)", mock.entitlementCalls.Load())
	}

	// Verify token was persisted.
	stored, err := store.Load("speechkit")
	if err != nil {
		t.Fatalf("store.Load() error: %v", err)
	}
	if stored == nil || stored.AccessToken != "int-access-token" {
		t.Errorf("stored token AccessToken = %v, want %q", stored, "int-access-token")
	}
}

// TestIntegration_TokenRefreshFlow tests automatic token refresh when the stored
// token is expired. The client should transparently call the refresh endpoint
// and return the new access token.
func TestIntegration_TokenRefreshFlow(t *testing.T) {
	mock := &mockAPI{
		refreshHandler: func(w http.ResponseWriter, r *http.Request) {
			var req refreshTokenRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode refresh request: %v", err)
			}
			if req.RefreshToken != "expired-refresh-token" {
				t.Errorf("RefreshToken = %q, want %q", req.RefreshToken, "expired-refresh-token")
			}
			if req.Tool != "speechkit" {
				t.Errorf("Tool = %q, want %q", req.Tool, "speechkit")
			}
			writeJSON(w, authResponse{
				Token: TokenPair{
					AccessToken:  "refreshed-access-token",
					RefreshToken: "refreshed-refresh-token",
					ExpiresAt:    time.Now().Add(1 * time.Hour),
					UserID:       "usr-integration",
				},
			})
		},
	}

	srv := httptest.NewServer(mock)
	defer srv.Close()

	// Pre-seed the store with an expired token so the client loads it on creation.
	store := newMemStore()
	expiredToken := &TokenPair{
		AccessToken:  "expired-access-token",
		RefreshToken: "expired-refresh-token",
		ExpiresAt:    time.Now().Add(-1 * time.Hour), // expired
		UserID:       "usr-integration",
	}
	if err := store.Save("speechkit", expiredToken); err != nil {
		t.Fatalf("store.Save() error: %v", err)
	}

	ctx := context.Background()

	c, err := New(Config{
		BaseURL:     srv.URL,
		ToolName:    "speechkit",
		ToolVersion: "0.1.0",
		TokenStore:  store,
		HTTPClient:  &http.Client{Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Client should have loaded the expired token from the store.
	if !c.IsAuthenticated() {
		t.Fatal("expected client to be authenticated (with expired token from store)")
	}

	// GetAccessToken should detect expiration and trigger refresh.
	token, err := c.GetAccessToken(ctx)
	if err != nil {
		t.Fatalf("GetAccessToken() error: %v", err)
	}
	if token != "refreshed-access-token" {
		t.Errorf("GetAccessToken() = %q, want %q", token, "refreshed-access-token")
	}

	// Refresh endpoint should have been called exactly once.
	if mock.refreshCalls.Load() != 1 {
		t.Errorf("refresh API called %d times, want 1", mock.refreshCalls.Load())
	}

	// Subsequent call should return the refreshed token without another refresh.
	token2, err := c.GetAccessToken(ctx)
	if err != nil {
		t.Fatalf("second GetAccessToken() error: %v", err)
	}
	if token2 != "refreshed-access-token" {
		t.Errorf("second GetAccessToken() = %q, want %q", token2, "refreshed-access-token")
	}
	if mock.refreshCalls.Load() != 1 {
		t.Errorf("refresh API called %d times after second GetAccessToken, want 1", mock.refreshCalls.Load())
	}

	// Verify the refreshed token was persisted to the store.
	stored, err := store.Load("speechkit")
	if err != nil {
		t.Fatalf("store.Load() error: %v", err)
	}
	if stored == nil || stored.AccessToken != "refreshed-access-token" {
		t.Errorf("stored token AccessToken = %v, want %q", stored, "refreshed-access-token")
	}
	if stored.RefreshToken != "refreshed-refresh-token" {
		t.Errorf("stored token RefreshToken = %q, want %q", stored.RefreshToken, "refreshed-refresh-token")
	}
}

// TestIntegration_OfflineResilience tests that cached entitlements survive
// when the API server becomes unreachable. After authenticating and caching
// entitlements, the test shuts down the mock server and verifies that
// GetEntitlements and HasFeature still work from the in-memory cache.
func TestIntegration_OfflineResilience(t *testing.T) {
	mock := &mockAPI{
		verifyHandler: func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, integrationAuthResponse())
		},
		entitlementsHandler: func(w http.ResponseWriter, r *http.Request) {
			t.Error("entitlements endpoint should not be called; cache should be used")
			http.Error(w, "unexpected", http.StatusInternalServerError)
		},
	}

	srv := httptest.NewServer(mock)
	// Do NOT defer srv.Close() -- we close it mid-test to simulate offline.

	store := newMemStore()
	ctx := context.Background()

	c, err := New(Config{
		BaseURL:     srv.URL,
		ToolName:    "speechkit",
		ToolVersion: "0.1.0",
		TokenStore:  store,
		HTTPClient:  &http.Client{Timeout: 2 * time.Second},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Step 1: Authenticate successfully while server is up.
	_, err = c.AuthenticateWithAPIKey(ctx, "offline-key")
	if err != nil {
		t.Fatalf("AuthenticateWithAPIKey() error: %v", err)
	}

	// Step 2: GetEntitlements returns cached from auth response.
	ent, err := c.GetEntitlements(ctx)
	if err != nil {
		t.Fatalf("GetEntitlements() (online) error: %v", err)
	}
	if ent.Tool != "speechkit" {
		t.Errorf("Entitlements.Tool = %q, want %q", ent.Tool, "speechkit")
	}

	// Step 3: Shut down the mock server to simulate going offline.
	srv.Close()

	// Step 4: GetEntitlements still returns cached result (cache TTL is 24h).
	entOffline, err := c.GetEntitlements(ctx)
	if err != nil {
		t.Fatalf("GetEntitlements() (offline) error: %v", err)
	}
	if entOffline.Tool != "speechkit" {
		t.Errorf("offline Entitlements.Tool = %q, want %q", entOffline.Tool, "speechkit")
	}
	if len(entOffline.Features) != 3 {
		t.Errorf("offline Entitlements.Features count = %d, want 3", len(entOffline.Features))
	}

	// Step 5: HasFeature still works from cache.
	has, err := c.HasFeature(ctx, "whisper_local")
	if err != nil {
		t.Fatalf("HasFeature(whisper_local) (offline) error: %v", err)
	}
	if !has {
		t.Error("HasFeature(whisper_local) (offline) = false, want true")
	}

	has, err = c.HasFeature(ctx, "cloud_export")
	if err != nil {
		t.Fatalf("HasFeature(cloud_export) (offline) error: %v", err)
	}
	if has {
		t.Error("HasFeature(cloud_export) (offline) = true, want false")
	}

	// Verify max_duration feature value is accessible offline.
	val, err := c.GetFeatureValue(ctx, "max_duration")
	if err != nil {
		t.Fatalf("GetFeatureValue(max_duration) (offline) error: %v", err)
	}
	if val != float64(600) {
		t.Errorf("GetFeatureValue(max_duration) (offline) = %v, want 600", val)
	}
}
