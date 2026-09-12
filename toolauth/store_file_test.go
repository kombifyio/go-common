package toolauth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileStore_SaveLoadRoundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)

	store := &FileStore{}
	token := &TokenPair{
		AccessToken:  "access-roundtrip",
		RefreshToken: "refresh-roundtrip",
		ExpiresAt:    time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC),
		UserID:       "usr-roundtrip",
	}

	if err := store.Save("testkit", token); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	loaded, err := store.Load("testkit")
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if loaded == nil {
		t.Fatal("Load() returned nil")
	}

	if loaded.AccessToken != token.AccessToken {
		t.Errorf("AccessToken = %q, want %q", loaded.AccessToken, token.AccessToken)
	}
	if loaded.RefreshToken != token.RefreshToken {
		t.Errorf("RefreshToken = %q, want %q", loaded.RefreshToken, token.RefreshToken)
	}
	if !loaded.ExpiresAt.Equal(token.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", loaded.ExpiresAt, token.ExpiresAt)
	}
	if loaded.UserID != token.UserID {
		t.Errorf("UserID = %q, want %q", loaded.UserID, token.UserID)
	}
}

func TestFileStore_LoadNonexistent(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)

	store := &FileStore{}

	loaded, err := store.Load("nonexistent-tool")
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if loaded != nil {
		t.Errorf("Load() = %v, want nil for nonexistent file", loaded)
	}
}

func TestFileStore_Delete(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)

	store := &FileStore{}
	token := &TokenPair{
		AccessToken:  "to-delete",
		RefreshToken: "refresh-delete",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		UserID:       "usr-del",
	}

	if err := store.Save("delkit", token); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Verify it exists.
	loaded, err := store.Load("delkit")
	if err != nil {
		t.Fatalf("Load() after Save() error: %v", err)
	}
	if loaded == nil {
		t.Fatal("Load() after Save() returned nil")
	}

	// Delete.
	if err := store.Delete("delkit"); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	// Verify it is gone.
	loaded, err = store.Load("delkit")
	if err != nil {
		t.Fatalf("Load() after Delete() error: %v", err)
	}
	if loaded != nil {
		t.Errorf("Load() after Delete() = %v, want nil", loaded)
	}
}

func TestFileStore_DeleteNonexistent(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)

	store := &FileStore{}

	// Deleting a nonexistent file should not error.
	if err := store.Delete("no-such-tool"); err != nil {
		t.Fatalf("Delete() on nonexistent file returned error: %v", err)
	}
}

func TestFileStore_Encryption(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)

	store := &FileStore{}
	token := &TokenPair{
		AccessToken:  "super-secret-token-12345",
		RefreshToken: "super-secret-refresh-67890",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		UserID:       "usr-secret",
	}

	if err := store.Save("enctest", token); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Read the raw file contents.
	path := filepath.Join(tmpDir, ".kombify", "enctest", "token.json")
	rawData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}

	// Verify the file is not plain JSON.
	var decoded TokenPair
	if json.Unmarshal(rawData, &decoded) == nil && decoded.AccessToken == token.AccessToken {
		t.Error("saved file contains plaintext JSON -- expected encrypted data")
	}

	// Verify the access token string does not appear in the raw bytes.
	rawStr := string(rawData)
	if contains(rawStr, token.AccessToken) {
		t.Error("raw file contains plaintext access token")
	}
	if contains(rawStr, token.RefreshToken) {
		t.Error("raw file contains plaintext refresh token")
	}
}

func TestFileStore_SaveOverwrite(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)

	store := &FileStore{}

	token1 := &TokenPair{
		AccessToken:  "first-token",
		RefreshToken: "first-refresh",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		UserID:       "usr-1",
	}
	if err := store.Save("overwrite-test", token1); err != nil {
		t.Fatalf("Save(token1) error: %v", err)
	}

	token2 := &TokenPair{
		AccessToken:  "second-token",
		RefreshToken: "second-refresh",
		ExpiresAt:    time.Now().Add(2 * time.Hour),
		UserID:       "usr-2",
	}
	if err := store.Save("overwrite-test", token2); err != nil {
		t.Fatalf("Save(token2) error: %v", err)
	}

	loaded, err := store.Load("overwrite-test")
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if loaded == nil {
		t.Fatal("Load() returned nil")
	}
	if loaded.AccessToken != "second-token" {
		t.Errorf("AccessToken = %q, want %q (overwrite should use latest)", loaded.AccessToken, "second-token")
	}
	if loaded.UserID != "usr-2" {
		t.Errorf("UserID = %q, want %q", loaded.UserID, "usr-2")
	}
}

// contains reports whether s contains substr.
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
