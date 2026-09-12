package oidcclient

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestNewProviderValidatesConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  ProviderConfig
	}{
		{"missing id", ProviderConfig{Kind: KindPocketID, Issuer: "https://i", ClientID: "a"}},
		{"missing issuer", ProviderConfig{ID: "p", Kind: KindPocketID, ClientID: "a"}},
		{"missing client id", ProviderConfig{ID: "p", Kind: KindPocketID, Issuer: "https://i"}},
		{"unsupported kind", ProviderConfig{ID: "p", Kind: "saml", Issuer: "https://i", ClientID: "a"}},
		{"non-http issuer", ProviderConfig{ID: "p", Kind: KindPocketID, Issuer: "javascript:alert(1)", ClientID: "a"}},
		{"relative issuer", ProviderConfig{ID: "p", Kind: KindPocketID, Issuer: "/oidc", ClientID: "a"}},
		{"issuer userinfo", ProviderConfig{ID: "p", Kind: KindPocketID, Issuer: "https://user@example.com", ClientID: "a"}},
		{"non-http authorization url", ProviderConfig{ID: "p", Kind: KindPocketID, Issuer: "https://i", ClientID: "a", AuthorizationURL: "javascript:alert(1)"}},
		{"relative token url", ProviderConfig{ID: "p", Kind: KindPocketID, Issuer: "https://i", ClientID: "a", TokenURL: "/token"}},
		{"scheme-relative jwks url", ProviderConfig{ID: "p", Kind: KindPocketID, Issuer: "https://i", ClientID: "a", JWKSURL: "//evil.example/jwks"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewProvider(c.cfg); err == nil {
				t.Fatalf("expected error")
			}
		})
	}
}

func TestNewProviderDerivesURLs(t *testing.T) {
	p, err := NewProvider(ProviderConfig{ID: "primary", Kind: KindPocketID, Issuer: "https://id.example/", ClientID: "kombi"})
	if err != nil {
		t.Fatal(err)
	}
	if p.ID() != "primary" || p.Kind() != KindPocketID {
		t.Fatalf("unexpected: %+v", p)
	}
	if got, want := p.Issuer(), "https://id.example/"; got != want {
		t.Fatalf("issuer: got=%q want=%q", got, want)
	}
	if got := p.AuthorizationURL(); got != "https://id.example/authorize" {
		t.Fatalf("authorization url: %q", got)
	}
	if got := p.TokenURL(); got != "https://id.example/oauth/token" {
		t.Fatalf("token url: %q", got)
	}
	got := p.Scopes()
	for _, required := range []string{"openid", "profile", "email"} {
		if !slices.Contains(got, required) {
			t.Fatalf("default scopes missing %q: %v", required, got)
		}
	}
}

func TestRegistry(t *testing.T) {
	r := NewRegistry()
	if r.Len() != 0 {
		t.Fatalf("len=%d", r.Len())
	}
	if _, err := r.Get("missing"); err == nil {
		t.Fatal("expected ErrUnknownProvider")
	}
	p, err := NewProvider(ProviderConfig{ID: "p1", Kind: KindAuth0, Issuer: "https://t.eu.auth0.com", ClientID: "kombi"})
	if err != nil {
		t.Fatal(err)
	}
	r.Add(p)
	got, err := r.Get("p1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID() != "p1" {
		t.Fatalf("unexpected id %q", got.ID())
	}
	if r.Len() != 1 {
		t.Fatalf("len=%d", r.Len())
	}
	ids := r.IDs()
	if len(ids) != 1 || ids[0] != "p1" {
		t.Fatalf("ids: %v", ids)
	}
}

func TestAuthCodeURL(t *testing.T) {
	p, err := NewProvider(ProviderConfig{ID: "p1", Kind: KindAuth0, Issuer: "https://t.eu.auth0.com", ClientID: "cid"})
	if err != nil {
		t.Fatal(err)
	}
	got := p.AuthCodeURL("http://localhost/callback", "state-1", "")
	if !strings.Contains(got, "client_id=cid") || !strings.Contains(got, "state=state-1") {
		t.Fatalf("auth code url: %q", got)
	}
	if strings.Contains(got, "code_challenge") {
		t.Fatalf("PKCE should be absent: %q", got)
	}
}

func TestAuthCodeURLWithPKCE(t *testing.T) {
	p, _ := NewProvider(ProviderConfig{ID: "p1", Kind: KindPocketID, Issuer: "https://id.example", ClientID: "cid"})
	got := p.AuthCodeURL("http://localhost/cb", "s", "challenge-xyz")
	if !strings.Contains(got, "code_challenge=challenge-xyz") || !strings.Contains(got, "code_challenge_method=S256") {
		t.Fatalf("PKCE params missing: %q", got)
	}
}

func TestAuthCodeURLPreservesProviderQuery(t *testing.T) {
	p, err := NewProvider(ProviderConfig{ID: "p1", Kind: KindAuth0, Issuer: "https://issuer.example", ClientID: "cid", AuthorizationURL: "https://issuer.example/authorize?connection=primary"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := url.Parse(p.AuthCodeURL("http://localhost/cb", "s", ""))
	if err != nil || got.Query().Get("connection") != "primary" {
		t.Fatalf("authorization query was not preserved: %q", got)
	}
}

func TestPKCEVerifier(t *testing.T) {
	v, c, err := PKCEVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if len(v) < 43 {
		t.Fatalf("verifier too short: %d", len(v))
	}
	// challenge must be S256(verifier)
	sum := sha256.Sum256([]byte(v))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if c != want {
		t.Fatalf("challenge mismatch: got=%q want=%q", c, want)
	}
}

func TestProviderKindAccepted(t *testing.T) {
	for _, k := range []Kind{KindPocketID, KindAuth0, KindPocketBase, KindGeneric} {
		if _, err := NewProvider(ProviderConfig{ID: "p", Kind: k, Issuer: "https://i", ClientID: "c"}); err != nil {
			t.Errorf("kind %q: %v", k, err)
		}
	}
}
