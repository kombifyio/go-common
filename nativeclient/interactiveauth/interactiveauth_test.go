package interactiveauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kombifyio/go-common/oidcclient"
)

func testProvider(t *testing.T, issuer string) *oidcclient.Provider {
	t.Helper()
	provider, err := oidcclient.NewProvider(oidcclient.ProviderConfig{
		ID:       "test",
		Kind:     oidcclient.KindGeneric,
		Issuer:   issuer,
		ClientID: "native-client",
		Scopes:   []string{"openid", "profile"},
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return provider
}

func TestLoopbackPKCE(t *testing.T) {
	var sawVerifier atomic.Value
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("code") != "test-code" {
			http.Error(w, "bad exchange", http.StatusBadRequest)
			return
		}
		sawVerifier.Store(r.PostForm.Get("code_verifier"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id_token":      "header.payload.signature",
			"access_token":  "access-1",
			"refresh_token": "refresh-1",
			"token_type":    "Bearer",
		})
	}))
	defer issuer.Close()

	provider := testProvider(t, issuer.URL)
	result, err := LoopbackPKCE(context.Background(), LoopbackConfig{
		Provider: provider,
		Timeout:  10 * time.Second,
		OpenBrowser: func(authURL string) error {
			parsed, err := url.Parse(authURL)
			if err != nil {
				return err
			}
			query := parsed.Query()
			if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" {
				t.Errorf("authorization URL missing PKCE challenge: %s", authURL)
			}
			redirect, err := url.Parse(query.Get("redirect_uri"))
			if err != nil {
				return err
			}
			if redirect.Hostname() != "127.0.0.1" {
				t.Errorf("redirect host = %q, want 127.0.0.1", redirect.Hostname())
			}
			// Simulate the browser hitting the loopback callback.
			go func() {
				callback := *redirect
				callback.RawQuery = url.Values{
					"state": {query.Get("state")},
					"code":  {"test-code"},
				}.Encode()
				resp, err := http.Get(callback.String())
				if err == nil {
					resp.Body.Close()
				}
			}()
			return nil
		},
	})
	if err != nil {
		t.Fatalf("LoopbackPKCE: %v", err)
	}
	if result.RefreshToken != "refresh-1" || result.AccessToken != "access-1" {
		t.Fatalf("unexpected tokens: %+v", result)
	}
	if verifier, _ := sawVerifier.Load().(string); verifier == "" {
		t.Fatal("token exchange did not carry the PKCE verifier")
	}
}

func TestLoopbackPKCERejectsStateMismatch(t *testing.T) {
	issuer := httptest.NewServer(http.NotFoundHandler())
	defer issuer.Close()
	provider := testProvider(t, issuer.URL)
	_, err := LoopbackPKCE(context.Background(), LoopbackConfig{
		Provider: provider,
		Timeout:  10 * time.Second,
		OpenBrowser: func(authURL string) error {
			parsed, _ := url.Parse(authURL)
			redirect, _ := url.Parse(parsed.Query().Get("redirect_uri"))
			go func() {
				callback := *redirect
				callback.RawQuery = url.Values{"state": {"forged"}, "code": {"x"}}.Encode()
				resp, err := http.Get(callback.String())
				if err == nil {
					resp.Body.Close()
				}
			}()
			return nil
		},
	})
	if !errors.Is(err, ErrCallback) {
		t.Fatalf("expected ErrCallback, got %v", err)
	}
}

func TestLoopbackPKCEAccessDenied(t *testing.T) {
	issuer := httptest.NewServer(http.NotFoundHandler())
	defer issuer.Close()
	provider := testProvider(t, issuer.URL)
	_, err := LoopbackPKCE(context.Background(), LoopbackConfig{
		Provider: provider,
		Timeout:  10 * time.Second,
		OpenBrowser: func(authURL string) error {
			parsed, _ := url.Parse(authURL)
			query := parsed.Query()
			redirect, _ := url.Parse(query.Get("redirect_uri"))
			go func() {
				callback := *redirect
				callback.RawQuery = url.Values{
					"state": {query.Get("state")},
					"error": {"access_denied"},
				}.Encode()
				resp, err := http.Get(callback.String())
				if err == nil {
					resp.Body.Close()
				}
			}()
			return nil
		},
	})
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("expected ErrAccessDenied, got %v", err)
	}
}

func TestDeviceGrant(t *testing.T) {
	var polls atomic.Int64
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/oauth/device/code", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("client_id") != "native-client" {
			http.Error(w, "bad client", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":               "device-1",
			"user_code":                 "WXYZ-ABCD",
			"verification_uri":          server.URL + "/activate",
			"verification_uri_complete": server.URL + "/activate?user_code=WXYZ-ABCD",
			"expires_in":                300,
			"interval":                  0,
		})
	})
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" ||
			r.PostForm.Get("device_code") != "device-1" {
			http.Error(w, "bad grant", http.StatusBadRequest)
			return
		}
		switch polls.Add(1) {
		case 1:
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
		case 2:
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "slow_down"})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "tool-token-1",
				"token_type":   "Bearer",
			})
		}
	})

	previousStep := slowDownStep
	slowDownStep = 10 * time.Millisecond
	t.Cleanup(func() { slowDownStep = previousStep })

	provider := testProvider(t, server.URL)
	prompted := false
	result, err := DeviceGrant(context.Background(), DeviceGrantConfig{
		Provider:     provider,
		Timeout:      30 * time.Second,
		PollInterval: 10 * time.Millisecond,
		Prompt: func(userCode, verificationURI, complete string) {
			prompted = true
			if userCode != "WXYZ-ABCD" || verificationURI == "" || complete == "" {
				t.Errorf("unexpected prompt: %q %q %q", userCode, verificationURI, complete)
			}
		},
	})
	if err != nil {
		t.Fatalf("DeviceGrant: %v", err)
	}
	if !prompted {
		t.Fatal("Prompt was not called")
	}
	if result.AccessToken != "tool-token-1" {
		t.Fatalf("unexpected token result: %+v", result)
	}
	if polls.Load() < 3 {
		t.Fatalf("expected at least 3 polls (pending, slow_down, success), got %d", polls.Load())
	}
}

func TestDeviceGrantAccessDenied(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/oauth/device/code", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":      "device-1",
			"user_code":        "WXYZ-ABCD",
			"verification_uri": server.URL + "/activate",
			"expires_in":       300,
			"interval":         0,
		})
	})
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "access_denied"})
	})
	provider := testProvider(t, server.URL)
	_, err := DeviceGrant(context.Background(), DeviceGrantConfig{
		Provider:     provider,
		Timeout:      30 * time.Second,
		PollInterval: 10 * time.Millisecond,
		Prompt:       func(string, string, string) {},
	})
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("expected ErrAccessDenied, got %v", err)
	}
}
