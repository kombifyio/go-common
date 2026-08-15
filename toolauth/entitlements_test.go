package toolauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// entitlementServer returns a test server that serves entitlement responses
// and counts how many times the entitlements endpoint was called.
func entitlementServer(t *testing.T, callCount *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/tools/entitlements":
			callCount.Add(1)
			if got := r.Header.Get("Authorization"); got == "" {
				t.Error("missing Authorization header on entitlements request")
			}
			tool := r.URL.Query().Get("tool")
			if tool != "speechkit" {
				t.Errorf("tool query param = %q, want %q", tool, "speechkit")
			}

			ent := Entitlements{
				Tool: "speechkit",
				Features: map[string]any{
					"whisper_local":    true,
					"max_duration":     float64(600),
					"disabled_feature": false,
					"string_feature":   "enabled",
					"nil_feature":      nil,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ent)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
}

// setTokenDirectly injects a valid token into the client without calling
// AuthenticateWithAPIKey, so no entitlements are cached from the auth response.
func setTokenDirectly(c *Client) {
	c.mu.Lock()
	c.token = &TokenPair{
		AccessToken:  "test-jwt",
		RefreshToken: "kbrt_test",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		UserID:       "usr-123",
	}
	c.mu.Unlock()
}

func TestGetEntitlements_FetchesFromAPI(t *testing.T) {
	var callCount atomic.Int32
	srv := entitlementServer(t, &callCount)
	defer srv.Close()

	c := newTestClient(t, srv.URL, newMemStore())
	setTokenDirectly(c)

	ent, err := c.GetEntitlements(context.Background())
	if err != nil {
		t.Fatalf("GetEntitlements() error: %v", err)
	}

	if ent.Tool != "speechkit" {
		t.Errorf("Tool = %q, want %q", ent.Tool, "speechkit")
	}
	if v, ok := ent.Features["whisper_local"]; !ok || v != true {
		t.Errorf("whisper_local = %v, want true", v)
	}
	if callCount.Load() != 1 {
		t.Errorf("entitlements endpoint called %d times, want 1", callCount.Load())
	}
}

func TestGetEntitlements_ReturnsCachedResult(t *testing.T) {
	var callCount atomic.Int32
	srv := entitlementServer(t, &callCount)
	defer srv.Close()

	c := newTestClient(t, srv.URL, newMemStore())
	setTokenDirectly(c)

	// First call fetches from API.
	_, err := c.GetEntitlements(context.Background())
	if err != nil {
		t.Fatalf("first GetEntitlements() error: %v", err)
	}
	if callCount.Load() != 1 {
		t.Fatalf("expected 1 API call after first fetch, got %d", callCount.Load())
	}

	// Second call should return cached result.
	ent2, err := c.GetEntitlements(context.Background())
	if err != nil {
		t.Fatalf("second GetEntitlements() error: %v", err)
	}

	if callCount.Load() != 1 {
		t.Errorf("entitlements endpoint called %d times, want 1 (second call should be cached)", callCount.Load())
	}
	if ent2.Tool != "speechkit" {
		t.Errorf("cached Tool = %q, want %q", ent2.Tool, "speechkit")
	}
}

func TestGetEntitlements_CachedFromAuth(t *testing.T) {
	// AuthenticateWithAPIKey caches entitlements from the auth response.
	// Verify that GetEntitlements returns those cached entitlements
	// without hitting the entitlements endpoint.
	var entCallCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/tools/auth/verify":
			w.Header().Set("Content-Type", "application/json")
			w.Write(testAuthResponse(t))
		case "/api/v1/tools/entitlements":
			entCallCount.Add(1)
			t.Error("entitlements endpoint should not be called when cache is warm")
			http.Error(w, "unexpected", http.StatusInternalServerError)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, newMemStore())
	_, err := c.AuthenticateWithAPIKey(context.Background(), "test-key")
	if err != nil {
		t.Fatalf("AuthenticateWithAPIKey() error: %v", err)
	}

	ent, err := c.GetEntitlements(context.Background())
	if err != nil {
		t.Fatalf("GetEntitlements() error: %v", err)
	}
	if ent.Tool != "speechkit" {
		t.Errorf("Tool = %q, want %q", ent.Tool, "speechkit")
	}
	if entCallCount.Load() != 0 {
		t.Errorf("entitlements endpoint called %d times, want 0", entCallCount.Load())
	}
}

func TestHasFeature(t *testing.T) {
	var callCount atomic.Int32
	srv := entitlementServer(t, &callCount)
	defer srv.Close()

	c := newTestClient(t, srv.URL, newMemStore())
	setTokenDirectly(c)

	// Pre-fetch to populate cache with full feature set.
	_, err := c.GetEntitlements(context.Background())
	if err != nil {
		t.Fatalf("GetEntitlements() error: %v", err)
	}

	tests := []struct {
		name    string
		feature string
		want    bool
	}{
		{
			name:    "existing bool true feature",
			feature: "whisper_local",
			want:    true,
		},
		{
			name:    "existing bool false feature",
			feature: "disabled_feature",
			want:    false,
		},
		{
			name:    "missing feature",
			feature: "nonexistent",
			want:    false,
		},
		{
			name:    "string feature is considered enabled",
			feature: "string_feature",
			want:    true,
		},
		{
			name:    "numeric feature is considered enabled",
			feature: "max_duration",
			want:    true,
		},
		{
			name:    "nil feature is considered disabled",
			feature: "nil_feature",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.HasFeature(context.Background(), tt.feature)
			if err != nil {
				t.Fatalf("HasFeature(%q) error: %v", tt.feature, err)
			}
			if got != tt.want {
				t.Errorf("HasFeature(%q) = %v, want %v", tt.feature, got, tt.want)
			}
		})
	}
}

func TestGetFeatureValue(t *testing.T) {
	var callCount atomic.Int32
	srv := entitlementServer(t, &callCount)
	defer srv.Close()

	c := newTestClient(t, srv.URL, newMemStore())
	setTokenDirectly(c)

	// Pre-fetch to populate cache with full feature set.
	_, err := c.GetEntitlements(context.Background())
	if err != nil {
		t.Fatalf("GetEntitlements() error: %v", err)
	}

	tests := []struct {
		name    string
		feature string
		wantNil bool
		wantVal any
	}{
		{
			name:    "numeric value",
			feature: "max_duration",
			wantVal: float64(600),
		},
		{
			name:    "bool value",
			feature: "whisper_local",
			wantVal: true,
		},
		{
			name:    "missing feature returns nil",
			feature: "nonexistent",
			wantNil: true,
		},
		{
			name:    "nil feature returns nil",
			feature: "nil_feature",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, err := c.GetFeatureValue(context.Background(), tt.feature)
			if err != nil {
				t.Fatalf("GetFeatureValue(%q) error: %v", tt.feature, err)
			}
			if tt.wantNil {
				if val != nil {
					t.Errorf("GetFeatureValue(%q) = %v, want nil", tt.feature, val)
				}
				return
			}
			if val != tt.wantVal {
				t.Errorf("GetFeatureValue(%q) = %v (%T), want %v (%T)",
					tt.feature, val, val, tt.wantVal, tt.wantVal)
			}
		})
	}
}

func TestInvalidateEntitlementCache(t *testing.T) {
	var callCount atomic.Int32
	srv := entitlementServer(t, &callCount)
	defer srv.Close()

	c := newTestClient(t, srv.URL, newMemStore())
	setTokenDirectly(c)

	// First fetch.
	_, err := c.GetEntitlements(context.Background())
	if err != nil {
		t.Fatalf("first GetEntitlements() error: %v", err)
	}
	if callCount.Load() != 1 {
		t.Fatalf("expected 1 call after first fetch, got %d", callCount.Load())
	}

	// Invalidate cache.
	c.InvalidateEntitlementCache()

	// Next fetch should hit the API again.
	_, err = c.GetEntitlements(context.Background())
	if err != nil {
		t.Fatalf("second GetEntitlements() error: %v", err)
	}
	if callCount.Load() != 2 {
		t.Errorf("expected 2 calls after invalidation, got %d", callCount.Load())
	}
}

func TestGetEntitlements_NotAuthenticated(t *testing.T) {
	c := newTestClient(t, "http://localhost", newMemStore())

	_, err := c.GetEntitlements(context.Background())
	if err == nil {
		t.Fatal("expected error for unauthenticated client")
	}
}

func TestHasFeature_NilFeatures(t *testing.T) {
	// Test HasFeature when the entitlements have nil Features map.
	c := newTestClient(t, "http://localhost", newMemStore())

	// Manually set entitlements with nil Features.
	c.mu.Lock()
	c.token = &TokenPair{
		AccessToken: "t",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	c.mu.Unlock()

	c.entMu.Lock()
	c.entitlements = &Entitlements{Tool: "speechkit", Features: nil}
	c.entFetchedAt = time.Now()
	c.entMu.Unlock()

	got, err := c.HasFeature(context.Background(), "anything")
	if err != nil {
		t.Fatalf("HasFeature() error: %v", err)
	}
	if got {
		t.Error("HasFeature() = true, want false for nil Features map")
	}
}
