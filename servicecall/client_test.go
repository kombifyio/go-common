package servicecall

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kombifyio/go-common/identity"
)

func TestNewClient_Validation(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"missing ServiceName", Config{Target: "ai", Secret: "s"}},
		{"missing Target", Config{ServiceName: "cloud", Secret: "s"}},
		{"missing Secret", Config{ServiceName: "cloud", Target: "ai"}},
	}
	for _, c := range cases {
		if _, err := NewClient(c.cfg); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
}

func TestNewClient_DefaultTTL(t *testing.T) {
	c, err := NewClient(Config{ServiceName: "cloud", Target: "ai", Secret: "s"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.cfg.TokenTTL != DefaultTokenTTL {
		t.Errorf("default TTL=%s want %s", c.cfg.TokenTTL, DefaultTokenTTL)
	}
}

func TestClient_Do_InjectsHeader(t *testing.T) {
	secret := "s"
	var seenToken string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenToken = r.Header.Get(HeaderServiceAuth)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := NewClient(Config{ServiceName: "cloud", Target: "ai", Secret: secret, TokenTTL: time.Minute})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	req, _ := http.NewRequest("GET", srv.URL, nil)
	resp, err := c.Do(context.Background(), req, nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	if seenToken == "" {
		t.Fatal("server did not receive X-Kombify-Service-Auth header")
	}
	claims, err := VerifyToken(seenToken, secret, "")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Svc != "cloud" || claims.Aud != "kombify-ai" {
		t.Errorf("claims mismatch: %+v", claims)
	}
	if claims.OnBehalfOf != nil {
		t.Errorf("expected no OnBehalfOf, got %+v", claims.OnBehalfOf)
	}
}

func TestClient_Do_WithOnBehalfOf(t *testing.T) {
	secret := "s"
	var seenToken string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenToken = r.Header.Get(HeaderServiceAuth)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, _ := NewClient(Config{ServiceName: "cloud", Target: "ai", Secret: secret, TokenTTL: time.Minute})
	obo := &OnBehalfOf{Sub: "user_1", OrgID: "org_a", Email: "u@x"}

	req, _ := http.NewRequest("GET", srv.URL, nil)
	resp, err := c.Do(context.Background(), req, obo)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	claims, err := VerifyToken(seenToken, secret, "")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.OnBehalfOf == nil || claims.OnBehalfOf.Sub != "user_1" {
		t.Errorf("OnBehalfOf not embedded: %+v", claims.OnBehalfOf)
	}
}

func TestOnBehalfOfIdentity(t *testing.T) {
	if OnBehalfOfIdentity(nil) != nil {
		t.Error("nil identity should return nil")
	}
	if OnBehalfOfIdentity(&identity.Identity{}) != nil {
		t.Error("identity without UserID should return nil")
	}
	id := &identity.Identity{UserID: "u1", OrgID: "o1", Email: "e@x", Roles: []string{"admin"}}
	obo := OnBehalfOfIdentity(id)
	if obo == nil || obo.Sub != "u1" || obo.OrgID != "o1" || obo.Email != "e@x" || obo.Roles[0] != "admin" {
		t.Errorf("conversion wrong: %+v", obo)
	}
}
