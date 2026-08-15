package toolauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// 1. Poll endpoint returns correct status codes
// ============================================================================

func TestSecurity_PollPendingReturns202(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted) // 202
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, newMemStore())
	_, err := c.PollDeviceCode(context.Background(), "pending-code")
	if !errors.Is(err, ErrAuthorizationPending) {
		t.Errorf("PollDeviceCode() with 202 returned error = %v, want ErrAuthorizationPending", err)
	}
}

func TestSecurity_PollExpiredReturns410(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone) // 410
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, newMemStore())
	_, err := c.PollDeviceCode(context.Background(), "expired-code")
	if !errors.Is(err, ErrDeviceCodeExpired) {
		t.Errorf("PollDeviceCode() with 410 returned error = %v, want ErrDeviceCodeExpired", err)
	}
}

func TestSecurity_PollSlowDownReturns429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests) // 429
		w.Write([]byte(`{"error":"slow_down"}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, newMemStore())
	_, err := c.PollDeviceCode(context.Background(), "throttled-code")
	if err == nil {
		t.Fatal("PollDeviceCode() with 429 returned nil error, want APIError")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusTooManyRequests {
		t.Errorf("APIError.StatusCode = %d, want %d", apiErr.StatusCode, http.StatusTooManyRequests)
	}
}

// ============================================================================
// 2. Refresh token isolation -- tool name is sent in refresh request
// ============================================================================

func TestSecurity_RefreshTokenSentWithCorrectTool(t *testing.T) {
	var capturedBody refreshTokenRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/tools/auth/refresh" {
			if err := json.NewDecoder(r.Body).Decode(&capturedBody); err != nil {
				t.Errorf("decode refresh request body: %v", err)
			}
			resp := authResponse{
				Token: TokenPair{
					AccessToken:  "refreshed-access",
					RefreshToken: "refreshed-refresh",
					ExpiresAt:    time.Now().Add(1 * time.Hour),
					UserID:       "usr-refresh",
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	store := newMemStore()
	c, err := New(Config{
		BaseURL:     srv.URL,
		ToolName:    "sim",
		ToolVersion: "1.2.0",
		TokenStore:  store,
		HTTPClient:  &http.Client{Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Inject an expired token to trigger refresh.
	c.mu.Lock()
	c.token = &TokenPair{
		AccessToken:  "expired-access",
		RefreshToken: "old-refresh-token",
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
		UserID:       "usr-refresh",
	}
	c.mu.Unlock()

	_, err = c.GetAccessToken(context.Background())
	if err != nil {
		t.Fatalf("GetAccessToken() error: %v", err)
	}

	if capturedBody.Tool != "sim" {
		t.Errorf("refresh request Tool = %q, want %q", capturedBody.Tool, "sim")
	}
	if capturedBody.RefreshToken != "old-refresh-token" {
		t.Errorf("refresh request RefreshToken = %q, want %q", capturedBody.RefreshToken, "old-refresh-token")
	}
}

// ============================================================================
// 3. FileStore encryption
// ============================================================================

func TestSecurity_FileStoreEncryptedContentNotPlaintext(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)

	store := &FileStore{}
	token := &TokenPair{
		AccessToken:  "highly-sensitive-access-token-xyz",
		RefreshToken: "highly-sensitive-refresh-token-abc",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		UserID:       "usr-enc",
	}

	if err := store.Save("enctest", token); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Read the raw file.
	path := filepath.Join(tmpDir, ".kombify", "enctest", "token.json")
	rawData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}

	rawStr := string(rawData)

	// The raw file must not contain the plaintext access token.
	if strings.Contains(rawStr, token.AccessToken) {
		t.Error("raw file contains plaintext access_token -- encryption not working")
	}
	if strings.Contains(rawStr, token.RefreshToken) {
		t.Error("raw file contains plaintext refresh_token -- encryption not working")
	}

	// Verify it is not valid JSON (encrypted data is binary).
	var decoded TokenPair
	if json.Unmarshal(rawData, &decoded) == nil && decoded.AccessToken == token.AccessToken {
		t.Error("saved file is plaintext JSON -- expected encrypted data")
	}
}

func TestSecurity_FileStoreDifferentToolNamesDifferentFiles(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)

	store := &FileStore{}

	tokenSpeechkit := &TokenPair{
		AccessToken:  "speechkit-token",
		RefreshToken: "speechkit-refresh",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		UserID:       "usr-sk",
	}
	tokenSim := &TokenPair{
		AccessToken:  "sim-token",
		RefreshToken: "sim-refresh",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		UserID:       "usr-sim",
	}

	if err := store.Save("speechkit", tokenSpeechkit); err != nil {
		t.Fatalf("Save(speechkit) error: %v", err)
	}
	if err := store.Save("sim", tokenSim); err != nil {
		t.Fatalf("Save(sim) error: %v", err)
	}

	// Verify different directories.
	pathSpeechkit := filepath.Join(tmpDir, ".kombify", "speechkit", "token.json")
	pathSim := filepath.Join(tmpDir, ".kombify", "sim", "token.json")

	if _, err := os.Stat(pathSpeechkit); err != nil {
		t.Errorf("speechkit token file not found: %v", err)
	}
	if _, err := os.Stat(pathSim); err != nil {
		t.Errorf("sim token file not found: %v", err)
	}

	if pathSpeechkit == pathSim {
		t.Error("speechkit and sim tokens stored in the same file path")
	}

	// Verify loading each tool returns its own token.
	loadedSK, err := store.Load("speechkit")
	if err != nil {
		t.Fatalf("Load(speechkit) error: %v", err)
	}
	loadedSim, err := store.Load("sim")
	if err != nil {
		t.Fatalf("Load(sim) error: %v", err)
	}

	if loadedSK.AccessToken != "speechkit-token" {
		t.Errorf("speechkit AccessToken = %q, want %q", loadedSK.AccessToken, "speechkit-token")
	}
	if loadedSim.AccessToken != "sim-token" {
		t.Errorf("sim AccessToken = %q, want %q", loadedSim.AccessToken, "sim-token")
	}
}

// ============================================================================
// 4. Token expiry buffer
// ============================================================================

func TestSecurity_TokenExpiredWithin30SecondBuffer(t *testing.T) {
	// Token expiring in 20 seconds should be treated as expired (30s buffer).
	token := &TokenPair{
		AccessToken:  "almost-expired",
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(20 * time.Second),
		UserID:       "usr-buffer",
	}

	if !token.IsExpired() {
		t.Error("token expiring in 20s should be treated as expired (30s buffer)")
	}
}

func TestSecurity_TokenNotExpiredOutsideBuffer(t *testing.T) {
	// Token expiring in 60 seconds should NOT be treated as expired.
	token := &TokenPair{
		AccessToken:  "still-valid",
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(60 * time.Second),
		UserID:       "usr-valid",
	}

	if token.IsExpired() {
		t.Error("token expiring in 60s should NOT be treated as expired (30s buffer)")
	}
}

func TestSecurity_TokenExactly30SecondsIsExpired(t *testing.T) {
	// Token expiring in exactly 30 seconds: time.Now().After(ExpiresAt - 30s)
	// -> time.Now().After(time.Now()) which is false.
	// But due to execution time, this is borderline. Test 29s instead.
	token := &TokenPair{
		AccessToken:  "borderline",
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(29 * time.Second),
		UserID:       "usr-border",
	}

	if !token.IsExpired() {
		t.Error("token expiring in 29s should be treated as expired (30s buffer)")
	}
}

func TestSecurity_TokenFarFutureNotExpired(t *testing.T) {
	token := &TokenPair{
		AccessToken:  "far-future",
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		UserID:       "usr-future",
	}

	if token.IsExpired() {
		t.Error("token expiring in 24h should not be treated as expired")
	}
}

func TestSecurity_TokenAlreadyPastIsExpired(t *testing.T) {
	token := &TokenPair{
		AccessToken:  "past",
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(-5 * time.Minute),
		UserID:       "usr-past",
	}

	if !token.IsExpired() {
		t.Error("token that expired 5 minutes ago should be treated as expired")
	}
}
