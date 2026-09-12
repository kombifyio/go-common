package profile

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestParseValidLocal(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "valid-local.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.DeploymentMode != ModeLocal {
		t.Errorf("DeploymentMode = %q, want %q", parsed.DeploymentMode, ModeLocal)
	}
	if parsed.OIDC.Flow != FlowLocalBootstrap {
		t.Errorf("OIDC.Flow = %q, want %q", parsed.OIDC.Flow, FlowLocalBootstrap)
	}
	if !parsed.HasCapability("techstack.runtime.read") {
		t.Error("expected capability techstack.runtime.read")
	}
	if parsed.HasCapability("techstack.tunnel") {
		t.Error("unexpected capability techstack.tunnel")
	}
	if parsed.Sync.OfflineWrite != OfflineWriteOutbox {
		t.Errorf("Sync.OfflineWrite = %q, want outbox", parsed.Sync.OfflineWrite)
	}
}

func TestParseRejectsNonObject(t *testing.T) {
	for _, raw := range []string{"[]", `"profile"`, "42", "not json"} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("Parse(%q): expected error", raw)
		}
	}
}

func TestFetch(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "valid-cloud.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != WellKnownPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	defer server.Close()

	parsed, err := Fetch(context.Background(), server.URL, server.Client())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if parsed.DeploymentMode != ModeCloud {
		t.Errorf("DeploymentMode = %q, want cloud", parsed.DeploymentMode)
	}
}

func TestFetchRejectsErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	if _, err := Fetch(context.Background(), server.URL, server.Client()); err == nil {
		t.Fatal("expected fetch error")
	}
}
