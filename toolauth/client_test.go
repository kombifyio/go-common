package toolauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// memStore is an in-memory TokenStore for testing.
type memStore struct {
	mu     sync.RWMutex
	tokens map[string]*TokenPair
}

func newMemStore() *memStore {
	return &memStore{tokens: make(map[string]*TokenPair)}
}

func (m *memStore) Save(toolName string, token *TokenPair) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[toolName] = token
	return nil
}

func (m *memStore) Load(toolName string) (*TokenPair, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tokens[toolName], nil
}

func (m *memStore) Delete(toolName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tokens, toolName)
	return nil
}

// testAuthResponse builds a JSON auth response matching the Cloud API format.
func testAuthResponse(t *testing.T) []byte {
	t.Helper()
	resp := authResponse{
		Token: TokenPair{
			AccessToken:  "test-jwt",
			RefreshToken: "kbrt_test",
			ExpiresAt:    time.Now().Add(1 * time.Hour),
			UserID:       "usr-123",
		},
		Entitlements: &Entitlements{
			Tool: "speechkit",
			Features: map[string]any{
				"whisper_local": true,
			},
			ExpiresAt: nil,
		},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal test auth response: %v", err)
	}
	return data
}

func newTestClient(t *testing.T, baseURL string, store TokenStore) *Client {
	t.Helper()
	c, err := New(Config{
		BaseURL:     baseURL,
		ToolName:    "speechkit",
		ToolVersion: "0.1.0",
		TokenStore:  store,
		HTTPClient:  &http.Client{Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	return c
}

func TestNew_Validation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name:    "missing BaseURL",
			cfg:     Config{ToolName: "test"},
			wantErr: true,
		},
		{
			name:    "missing ToolName",
			cfg:     Config{BaseURL: "http://localhost"},
			wantErr: true,
		},
		{
			name:    "rejects remote plaintext HTTP",
			cfg:     Config{BaseURL: "http://api.example", ToolName: "test", TokenStore: newMemStore()},
			wantErr: true,
		},
		{
			name:    "rejects non-HTTP scheme",
			cfg:     Config{BaseURL: "file:///tmp/api", ToolName: "test", TokenStore: newMemStore()},
			wantErr: true,
		},
		{
			name:    "rejects URL userinfo",
			cfg:     Config{BaseURL: "https://user@api.example", ToolName: "test", TokenStore: newMemStore()},
			wantErr: true,
		},
		{
			name:    "rejects URL query",
			cfg:     Config{BaseURL: "https://api.example?target=other", ToolName: "test", TokenStore: newMemStore()},
			wantErr: true,
		},
		{
			name: "valid config",
			cfg: Config{
				BaseURL:    "http://localhost",
				ToolName:   "test",
				TokenStore: newMemStore(),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNew_LoadsStoredToken(t *testing.T) {
	store := newMemStore()
	token := &TokenPair{
		AccessToken:  "stored-token",
		RefreshToken: "stored-refresh",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		UserID:       "usr-stored",
	}
	if err := store.Save("speechkit", token); err != nil {
		t.Fatalf("store.Save() error: %v", err)
	}

	c := newTestClient(t, "http://localhost", store)
	if !c.IsAuthenticated() {
		t.Error("expected client to be authenticated after loading stored token")
	}
}

func TestAuthenticateWithAPIKey_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/tools/auth/verify" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if got := r.Header.Get("X-API-Key"); got != "valid-key" {
			t.Errorf("X-API-Key = %q, want %q", got, "valid-key")
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want %q", got, "application/json")
		}

		var req authVerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		if req.Tool != "speechkit" {
			t.Errorf("request Tool = %q, want %q", req.Tool, "speechkit")
		}
		if req.Version != "0.1.0" {
			t.Errorf("request Version = %q, want %q", req.Version, "0.1.0")
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(testAuthResponse(t))
	}))
	defer srv.Close()

	store := newMemStore()
	c := newTestClient(t, srv.URL, store)

	result, err := c.AuthenticateWithAPIKey(context.Background(), "valid-key")
	if err != nil {
		t.Fatalf("AuthenticateWithAPIKey() error: %v", err)
	}

	if result.Token.AccessToken != "test-jwt" {
		t.Errorf("AccessToken = %q, want %q", result.Token.AccessToken, "test-jwt")
	}
	if result.Token.RefreshToken != "kbrt_test" {
		t.Errorf("RefreshToken = %q, want %q", result.Token.RefreshToken, "kbrt_test")
	}
	if result.Token.UserID != "usr-123" {
		t.Errorf("UserID = %q, want %q", result.Token.UserID, "usr-123")
	}
	if result.Entitlements == nil {
		t.Fatal("Entitlements is nil")
	}
	if result.Entitlements.Tool != "speechkit" {
		t.Errorf("Entitlements.Tool = %q, want %q", result.Entitlements.Tool, "speechkit")
	}
	if v, ok := result.Entitlements.Features["whisper_local"]; !ok || v != true {
		t.Errorf("Feature whisper_local = %v, want true", v)
	}

	// Verify token was persisted to store.
	stored, err := store.Load("speechkit")
	if err != nil {
		t.Fatalf("store.Load() error: %v", err)
	}
	if stored == nil || stored.AccessToken != "test-jwt" {
		t.Errorf("stored token = %v, want AccessToken=%q", stored, "test-jwt")
	}

	// Verify client is now authenticated.
	if !c.IsAuthenticated() {
		t.Error("expected IsAuthenticated() == true after successful auth")
	}
}

func TestAuthenticateWithAPIKey_InvalidKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid api key"}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, newMemStore())

	_, err := c.AuthenticateWithAPIKey(context.Background(), "bad-key")
	if err == nil {
		t.Fatal("expected error for invalid API key")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("APIError.StatusCode = %d, want %d", apiErr.StatusCode, http.StatusUnauthorized)
	}
}

func TestGetAccessToken_ReturnsCachedToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("unexpected HTTP request — token should have been cached")
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer srv.Close()

	store := newMemStore()
	c := newTestClient(t, srv.URL, store)

	// Inject a valid token directly.
	c.mu.Lock()
	c.token = &TokenPair{
		AccessToken:  "cached-token",
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		UserID:       "usr-1",
	}
	c.mu.Unlock()

	token, err := c.GetAccessToken(context.Background())
	if err != nil {
		t.Fatalf("GetAccessToken() error: %v", err)
	}
	if token != "cached-token" {
		t.Errorf("GetAccessToken() = %q, want %q", token, "cached-token")
	}
}

func TestGetAccessToken_RefreshesExpiredToken(t *testing.T) {
	refreshCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/tools/auth/refresh" {
			refreshCalled = true
			var req refreshTokenRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode refresh request: %v", err)
			}
			if req.RefreshToken != "old-refresh" {
				t.Errorf("RefreshToken = %q, want %q", req.RefreshToken, "old-refresh")
			}

			resp := authResponse{
				Token: TokenPair{
					AccessToken:  "new-access",
					RefreshToken: "new-refresh",
					ExpiresAt:    time.Now().Add(1 * time.Hour),
					UserID:       "usr-1",
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		t.Errorf("unexpected path: %s", r.URL.Path)
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	store := newMemStore()
	c := newTestClient(t, srv.URL, store)

	// Inject an expired token.
	c.mu.Lock()
	c.token = &TokenPair{
		AccessToken:  "expired-access",
		RefreshToken: "old-refresh",
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
		UserID:       "usr-1",
	}
	c.mu.Unlock()

	token, err := c.GetAccessToken(context.Background())
	if err != nil {
		t.Fatalf("GetAccessToken() error: %v", err)
	}
	if !refreshCalled {
		t.Error("expected refresh endpoint to be called")
	}
	if token != "new-access" {
		t.Errorf("GetAccessToken() = %q, want %q", token, "new-access")
	}
}

func TestGetAccessToken_NotAuthenticated(t *testing.T) {
	c := newTestClient(t, "http://localhost", newMemStore())

	_, err := c.GetAccessToken(context.Background())
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("GetAccessToken() error = %v, want %v", err, ErrNotAuthenticated)
	}
}

func TestLogout(t *testing.T) {
	store := newMemStore()
	c := newTestClient(t, "http://localhost", store)

	// Set up state.
	c.mu.Lock()
	c.token = &TokenPair{
		AccessToken:  "t",
		RefreshToken: "r",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		UserID:       "usr-1",
	}
	c.mu.Unlock()
	_ = store.Save("speechkit", c.token)

	c.entMu.Lock()
	c.entitlements = &Entitlements{Tool: "speechkit"}
	c.entFetchedAt = time.Now()
	c.entMu.Unlock()

	if err := c.Logout(context.Background()); err != nil {
		t.Fatalf("Logout() error: %v", err)
	}

	if c.IsAuthenticated() {
		t.Error("expected IsAuthenticated() == false after Logout")
	}

	// Token should be removed from store.
	stored, err := store.Load("speechkit")
	if err != nil {
		t.Fatalf("store.Load() error: %v", err)
	}
	if stored != nil {
		t.Error("expected stored token to be nil after Logout")
	}

	// Entitlements should be cleared.
	c.entMu.RLock()
	if c.entitlements != nil {
		t.Error("expected entitlements to be nil after Logout")
	}
	if !c.entFetchedAt.IsZero() {
		t.Error("expected entFetchedAt to be zero after Logout")
	}
	c.entMu.RUnlock()
}

func TestStartDeviceCodeFlow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/tools/auth/device-code" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}

		var req deviceCodeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if req.Tool != "speechkit" {
			t.Errorf("Tool = %q, want %q", req.Tool, "speechkit")
		}

		resp := DeviceCodeResponse{
			DeviceCode:      "dev-code-123",
			UserCode:        "ABCD-1234",
			VerificationURI: "https://kombify.io/device",
			ExpiresIn:       300,
			Interval:        5,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, newMemStore())
	resp, err := c.StartDeviceCodeFlow(context.Background())
	if err != nil {
		t.Fatalf("StartDeviceCodeFlow() error: %v", err)
	}

	if resp.DeviceCode != "dev-code-123" {
		t.Errorf("DeviceCode = %q, want %q", resp.DeviceCode, "dev-code-123")
	}
	if resp.UserCode != "ABCD-1234" {
		t.Errorf("UserCode = %q, want %q", resp.UserCode, "ABCD-1234")
	}
	if resp.VerificationURI != "https://kombify.io/device" {
		t.Errorf("VerificationURI = %q, want %q", resp.VerificationURI, "https://kombify.io/device")
	}
	if resp.ExpiresIn != 300 {
		t.Errorf("ExpiresIn = %d, want %d", resp.ExpiresIn, 300)
	}
	if resp.Interval != 5 {
		t.Errorf("Interval = %d, want %d", resp.Interval, 5)
	}
}

func TestPollDeviceCode_AuthorizationPending(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/tools/auth/device-code/poll" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, newMemStore())
	_, err := c.PollDeviceCode(context.Background(), "dev-code-123")
	if !errors.Is(err, ErrAuthorizationPending) {
		t.Errorf("PollDeviceCode() error = %v, want %v", err, ErrAuthorizationPending)
	}
}

func TestPollDeviceCode_DeviceCodeExpired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, newMemStore())
	_, err := c.PollDeviceCode(context.Background(), "dev-code-123")
	if !errors.Is(err, ErrDeviceCodeExpired) {
		t.Errorf("PollDeviceCode() error = %v, want %v", err, ErrDeviceCodeExpired)
	}
}

func TestPollDeviceCode_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/tools/auth/device-code/poll" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		var req deviceCodePollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if req.DeviceCode != "dev-code-123" {
			t.Errorf("DeviceCode = %q, want %q", req.DeviceCode, "dev-code-123")
		}
		if req.Tool != "speechkit" {
			t.Errorf("Tool = %q, want %q", req.Tool, "speechkit")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(testAuthResponse(t))
	}))
	defer srv.Close()

	store := newMemStore()
	c := newTestClient(t, srv.URL, store)

	result, err := c.PollDeviceCode(context.Background(), "dev-code-123")
	if err != nil {
		t.Fatalf("PollDeviceCode() error: %v", err)
	}

	if result.Token.AccessToken != "test-jwt" {
		t.Errorf("AccessToken = %q, want %q", result.Token.AccessToken, "test-jwt")
	}
	if result.Token.UserID != "usr-123" {
		t.Errorf("UserID = %q, want %q", result.Token.UserID, "usr-123")
	}
	if result.Entitlements == nil {
		t.Fatal("Entitlements is nil")
	}
	if result.Entitlements.Tool != "speechkit" {
		t.Errorf("Entitlements.Tool = %q, want %q", result.Entitlements.Tool, "speechkit")
	}

	// Verify token was stored.
	if !c.IsAuthenticated() {
		t.Error("expected IsAuthenticated() == true after successful poll")
	}
	stored, err := store.Load("speechkit")
	if err != nil {
		t.Fatalf("store.Load() error: %v", err)
	}
	if stored == nil || stored.AccessToken != "test-jwt" {
		t.Errorf("stored token = %v, want AccessToken=%q", stored, "test-jwt")
	}
}

func TestPollDeviceCode_UnexpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, newMemStore())
	_, err := c.PollDeviceCode(context.Background(), "dev-code-123")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("APIError.StatusCode = %d, want %d", apiErr.StatusCode, http.StatusInternalServerError)
	}
}
