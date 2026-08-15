package oidcclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiscoverSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 "https://issuer.example",
			"authorization_endpoint": "https://issuer.example/authorize",
			"token_endpoint":         "https://issuer.example/oauth/token",
			"jwks_uri":               "https://issuer.example/.well-known/jwks.json",
		})
	}))
	defer srv.Close()
	doc, err := Discover(context.Background(), srv.URL, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if doc.Issuer != "https://issuer.example" || doc.JWKSURI == "" {
		t.Fatalf("doc: %+v", doc)
	}
}

func TestDiscoverFailures(t *testing.T) {
	if _, err := Discover(context.Background(), "  ", nil); err == nil {
		t.Fatal("expected empty-issuer error")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := Discover(context.Background(), srv.URL, srv.Client()); err == nil {
		t.Fatal("expected status-500 error")
	}
}

func TestApplyDiscoveryFillsBlanks(t *testing.T) {
	cfg := ProviderConfig{Issuer: "https://i", ClientID: "c"}
	doc := &DiscoveryDocument{
		AuthorizationEndpoint: "https://i/auth",
		TokenEndpoint:         "https://i/token",
		JWKSURI:               "https://i/jwks",
	}
	ApplyDiscovery(&cfg, doc)
	if cfg.AuthorizationURL != "https://i/auth" || cfg.TokenURL != "https://i/token" || cfg.JWKSURL != "https://i/jwks" {
		t.Fatalf("apply: %+v", cfg)
	}
}

func TestApplyDiscoveryDoesNotOverwrite(t *testing.T) {
	cfg := ProviderConfig{
		Issuer:           "https://i",
		AuthorizationURL: "https://override/auth",
		TokenURL:         "https://override/token",
		JWKSURL:          "https://override/jwks",
	}
	doc := &DiscoveryDocument{
		AuthorizationEndpoint: "https://i/auth",
		TokenEndpoint:         "https://i/token",
		JWKSURI:               "https://i/jwks",
	}
	ApplyDiscovery(&cfg, doc)
	if cfg.AuthorizationURL != "https://override/auth" {
		t.Fatalf("authorization URL was overwritten: %q", cfg.AuthorizationURL)
	}
}

func TestHTTPCodeExchangerSuccess(t *testing.T) {
	var lastBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		lastBody = r.PostForm.Encode()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id_token":     "id-token-xyz",
			"access_token": "at-1",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()
	p, _ := NewProvider(ProviderConfig{
		ID: "p", Kind: KindPocketID, Issuer: "https://i", ClientID: "cid",
		TokenURL: srv.URL,
	})
	exch := NewHTTPCodeExchanger()
	exch.Client = srv.Client()
	res, err := exch.ExchangeCode(context.Background(), p, CodeExchangeRequest{
		Code: "code-1", RedirectURI: "http://localhost/cb", PKCEVerifier: "v123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IDToken != "id-token-xyz" || res.AccessToken != "at-1" {
		t.Fatalf("result: %+v", res)
	}
	for _, want := range []string{"grant_type=authorization_code", "code=code-1", "code_verifier=v123", "client_id=cid"} {
		if !strings.Contains(lastBody, want) {
			t.Errorf("body missing %q: %s", want, lastBody)
		}
	}
}

func TestHTTPCodeExchangerErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
	}))
	defer srv.Close()
	p, _ := NewProvider(ProviderConfig{ID: "p", Kind: KindAuth0, Issuer: "https://i", ClientID: "cid", TokenURL: srv.URL})
	exch := &HTTPCodeExchanger{Client: srv.Client()}
	if _, err := exch.ExchangeCode(context.Background(), p, CodeExchangeRequest{Code: "c", RedirectURI: "http://x/cb"}); err == nil {
		t.Fatal("expected error on 400")
	}
	if _, err := exch.ExchangeCode(context.Background(), p, CodeExchangeRequest{Code: "", RedirectURI: "http://x"}); err == nil {
		t.Fatal("expected error on missing code")
	}
	if _, err := exch.ExchangeCode(context.Background(), p, CodeExchangeRequest{Code: "c", RedirectURI: ""}); err == nil {
		t.Fatal("expected error on missing redirect uri")
	}
}

func TestHTTPCodeExchangerSendsBasicAuthForConfidential(t *testing.T) {
	var gotBasic bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, ok := r.BasicAuth()
		gotBasic = ok
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id_token": "x"})
	}))
	defer srv.Close()
	p, _ := NewProvider(ProviderConfig{
		ID: "p", Kind: KindAuth0, Issuer: "https://i",
		ClientID: "cid", ClientSecret: "shh", TokenURL: srv.URL,
	})
	exch := &HTTPCodeExchanger{Client: srv.Client()}
	if _, err := exch.ExchangeCode(context.Background(), p, CodeExchangeRequest{Code: "c", RedirectURI: "http://x/cb"}); err != nil {
		t.Fatal(err)
	}
	if !gotBasic {
		t.Fatal("expected Basic auth header for confidential client")
	}
}

func TestIdentityFromClaims(t *testing.T) {
	c := &Claims{
		Subject: "user-1",
		Email:   "u@example.com",
		Raw: map[string]interface{}{
			"org_id": "org-7",
			"tier":   "pro",
			"roles":  []interface{}{"admin", "ops"},
		},
	}
	id := IdentityFromClaims(c)
	if id == nil || id.UserID != "user-1" || id.Email != "u@example.com" {
		t.Fatalf("identity: %+v", id)
	}
	if id.OrgID != "org-7" || id.Tier != "pro" {
		t.Fatalf("identity: %+v", id)
	}
	if len(id.Roles) != 2 || id.Roles[0] != "admin" {
		t.Fatalf("roles: %v", id.Roles)
	}
	if !id.IsAuthenticated() {
		t.Fatal("expected authenticated")
	}
}

func TestIdentityFromClaimsRolesString(t *testing.T) {
	c := &Claims{
		Subject: "u",
		Raw:     map[string]interface{}{"roles": "admin,ops, viewer"},
	}
	id := IdentityFromClaims(c)
	if len(id.Roles) != 3 || id.Roles[2] != "viewer" {
		t.Fatalf("roles: %v", id.Roles)
	}
}

func TestIdentityFromClaimsSingleRole(t *testing.T) {
	c := &Claims{
		Subject: "u",
		Raw:     map[string]interface{}{"role": "admin"},
	}
	id := IdentityFromClaims(c)
	if len(id.Roles) != 1 || id.Roles[0] != "admin" {
		t.Fatalf("roles: %v", id.Roles)
	}
}

func TestIdentityFromClaimsNilSafe(t *testing.T) {
	if IdentityFromClaims(nil) != nil {
		t.Fatal("expected nil for nil claims")
	}
}

func TestIdentityFromClaimsAlternativeKeys(t *testing.T) {
	c := &Claims{
		Subject: "u",
		Raw:     map[string]interface{}{"project_id": "p1", "plan": "free"},
	}
	id := IdentityFromClaims(c)
	if id.OrgID != "p1" || id.Tier != "free" {
		t.Fatalf("identity: %+v", id)
	}
}
