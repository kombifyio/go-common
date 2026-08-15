package servicecall

import (
	"strings"
	"testing"
	"time"
)

func TestIssueAndVerify_Roundtrip(t *testing.T) {
	cfg := Config{ServiceName: "cloud", Secret: "s3cret", TokenTTL: time.Minute}
	obo := &OnBehalfOf{Sub: "user_123", OrgID: "org_abc", Email: "u@example.com", Roles: []string{"admin"}}

	tok, err := IssueToken(cfg, "ai", obo, "req-1")
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	if strings.Count(tok, ".") != 2 {
		t.Fatalf("expected 3-part JWT, got %q", tok)
	}

	claims, err := VerifyToken(tok, cfg.Secret, "")
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims.Iss != "kombify-cloud" {
		t.Errorf("iss=%q want kombify-cloud", claims.Iss)
	}
	if claims.Aud != "kombify-ai" {
		t.Errorf("aud=%q want kombify-ai", claims.Aud)
	}
	if claims.Svc != "cloud" {
		t.Errorf("svc=%q want cloud", claims.Svc)
	}
	if claims.RequestID != "req-1" {
		t.Errorf("req_id=%q want req-1", claims.RequestID)
	}
	if claims.OnBehalfOf == nil || claims.OnBehalfOf.Sub != "user_123" {
		t.Errorf("OnBehalfOf lost: %+v", claims.OnBehalfOf)
	}
	if claims.OnBehalfOf.Roles[0] != "admin" {
		t.Errorf("roles lost: %+v", claims.OnBehalfOf.Roles)
	}
}

func TestIssueToken_EmptySecret(t *testing.T) {
	_, err := IssueToken(Config{ServiceName: "cloud"}, "ai", nil, "")
	if err != ErrEmptySecret {
		t.Fatalf("want ErrEmptySecret, got %v", err)
	}
}

func TestVerifyToken_BadSignature(t *testing.T) {
	tok, _ := IssueToken(Config{ServiceName: "cloud", Secret: "a"}, "ai", nil, "")
	if _, err := VerifyToken(tok, "wrong-secret", ""); err != ErrBadSignature {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestVerifyToken_Malformed(t *testing.T) {
	cases := []string{"", "a.b", "a.b.c.d", "not-base64.!!.bad"}
	for _, c := range cases {
		if _, err := VerifyToken(c, "s", ""); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestVerifyToken_Expired(t *testing.T) {
	secret := "s"
	past := time.Now().Add(-time.Hour)
	claims := Claims{
		Iss: "kombify-cloud",
		Aud: "kombify-ai",
		Iat: past.Unix(),
		Exp: past.Add(time.Minute).Unix(), // expired 59 min ago
		Svc: "cloud",
	}
	tok, err := signClaims(claims, secret)
	if err != nil {
		t.Fatalf("signClaims: %v", err)
	}
	if _, err := VerifyToken(tok, secret, ""); err != ErrExpired {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestVerifyToken_NotYetValid(t *testing.T) {
	secret := "s"
	future := time.Now().Add(time.Hour)
	claims := Claims{
		Iss: "kombify-cloud",
		Aud: "kombify-ai",
		Iat: future.Unix(),
		Exp: future.Add(time.Minute).Unix(),
		Svc: "cloud",
	}
	tok, err := signClaims(claims, secret)
	if err != nil {
		t.Fatalf("signClaims: %v", err)
	}
	if _, err := VerifyToken(tok, secret, ""); err != ErrNotYetValid {
		t.Fatalf("want ErrNotYetValid, got %v", err)
	}
}

func TestVerifyToken_DualKey_NextAcceptsOldSecret(t *testing.T) {
	// Rotation scenario: a token was signed with the previous secret.
	// Verifier has rotated: new primary, old is now "next".
	old := "old-secret"
	newPrimary := "new-secret"
	tok, err := IssueToken(Config{ServiceName: "cloud", Secret: old, TokenTTL: time.Minute}, "ai", nil, "")
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	if _, err := VerifyToken(tok, newPrimary, old); err != nil {
		t.Fatalf("rotation verify failed: %v", err)
	}
	if _, err := VerifyToken(tok, newPrimary, ""); err != ErrBadSignature {
		t.Fatalf("without next secret, want ErrBadSignature, got %v", err)
	}
}

func TestVerifyToken_DualKey_PrimaryPreferred(t *testing.T) {
	secret := "s"
	tok, _ := IssueToken(Config{ServiceName: "cloud", Secret: secret, TokenTTL: time.Minute}, "ai", nil, "")
	// primary matches, next is garbage — must still accept
	if _, err := VerifyToken(tok, secret, "garbage"); err != nil {
		t.Fatalf("primary-first verify: %v", err)
	}
}
