package oidcclient

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newJWKSServer(t *testing.T, kid string, key *rsa.PublicKey) *httptest.Server {
	t.Helper()
	doc := map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": kid,
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}},
	}
	b, _ := json.Marshal(doc)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}))
}

func signToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func TestNewVerifierConfigValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  VerifierConfig
	}{
		{"missing issuer", VerifierConfig{Audience: "a", JWKSURL: "https://x/.well-known/jwks.json"}},
		{"missing audience", VerifierConfig{Issuer: "https://i", JWKSURL: "https://x/.well-known/jwks.json"}},
		{"missing jwks", VerifierConfig{Issuer: "https://i", Audience: "a"}},
		{"max < min", VerifierConfig{Issuer: "https://i", Audience: "a", JWKSURL: "https://x", JWKSRefreshMin: time.Minute, JWKSRefreshMax: time.Second}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewVerifier(c.cfg); err == nil {
				t.Fatalf("expected config error")
			}
		})
	}
}

func TestVerifySuccess(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newJWKSServer(t, "kid-1", &key.PublicKey)
	defer srv.Close()
	v, err := NewVerifier(VerifierConfig{
		Issuer:   "https://issuer.example",
		Audience: "kombi",
		JWKSURL:  srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	tok := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss":   "https://issuer.example",
		"aud":   "kombi",
		"sub":   "user-42",
		"email": "u@example.com",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Minute).Unix(),
	})
	c, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if c.Subject != "user-42" || c.Email != "u@example.com" {
		t.Fatalf("unexpected claims: %+v", c)
	}
	if len(c.Audience) != 1 || c.Audience[0] != "kombi" {
		t.Fatalf("audience: %v", c.Audience)
	}
}

func TestVerifyAudienceMismatch(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newJWKSServer(t, "kid-1", &key.PublicKey)
	defer srv.Close()
	v, _ := NewVerifier(VerifierConfig{Issuer: "https://i", Audience: "kombi", JWKSURL: srv.URL})
	tok := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": "https://i", "aud": "other", "sub": "u", "exp": time.Now().Add(time.Minute).Unix(),
	})
	if _, err := v.Verify(context.Background(), tok); err != ErrAudienceMismatch {
		t.Fatalf("want ErrAudienceMismatch, got %v", err)
	}
}

func TestVerifyIssuerMismatch(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newJWKSServer(t, "kid-1", &key.PublicKey)
	defer srv.Close()
	v, _ := NewVerifier(VerifierConfig{Issuer: "https://i", Audience: "a", JWKSURL: srv.URL})
	tok := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": "https://other", "aud": "a", "sub": "u", "exp": time.Now().Add(time.Minute).Unix(),
	})
	if _, err := v.Verify(context.Background(), tok); err != ErrIssuerMismatch {
		t.Fatalf("want ErrIssuerMismatch, got %v", err)
	}
}

func TestVerifyExpired(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newJWKSServer(t, "kid-1", &key.PublicKey)
	defer srv.Close()
	v, _ := NewVerifier(VerifierConfig{Issuer: "https://i", Audience: "a", JWKSURL: srv.URL})
	tok := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": "https://i", "aud": "a", "sub": "u", "exp": time.Now().Add(-time.Minute).Unix(),
	})
	if _, err := v.Verify(context.Background(), tok); err != ErrTokenExpired {
		t.Fatalf("want ErrTokenExpired, got %v", err)
	}
}

func TestVerifyFutureIssuedAtRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newJWKSServer(t, "kid-1", &key.PublicKey)
	defer srv.Close()
	v, _ := NewVerifier(VerifierConfig{Issuer: "https://i", Audience: "a", JWKSURL: srv.URL})
	now := time.Now()
	tok := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": "https://i",
		"aud": "a",
		"sub": "u",
		"iat": now.Add(time.Minute).Unix(),
		"exp": now.Add(2 * time.Minute).Unix(),
	})
	if _, err := v.Verify(context.Background(), tok); err != ErrTokenNotYetValid {
		t.Fatalf("want ErrTokenNotYetValid, got %v", err)
	}
}

func TestVerifyClockSkewAllowsNearFutureIssuedAt(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newJWKSServer(t, "kid-1", &key.PublicKey)
	defer srv.Close()
	v, _ := NewVerifier(VerifierConfig{
		Issuer:    "https://i",
		Audience:  "a",
		JWKSURL:   srv.URL,
		ClockSkew: 2 * time.Minute,
	})
	now := time.Now()
	tok := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": "https://i",
		"aud": "a",
		"sub": "u",
		"iat": now.Add(time.Minute).Unix(),
		"exp": now.Add(3 * time.Minute).Unix(),
	})
	claims, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("verify with skew: %v", err)
	}
	if claims.Subject != "u" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestVerifyClockSkewAllowsRecentExpiry(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newJWKSServer(t, "kid-1", &key.PublicKey)
	defer srv.Close()
	v, _ := NewVerifier(VerifierConfig{
		Issuer:    "https://i",
		Audience:  "a",
		JWKSURL:   srv.URL,
		ClockSkew: time.Minute,
	})
	now := time.Now()
	tok := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": "https://i",
		"aud": "a",
		"sub": "u",
		"iat": now.Add(-2 * time.Minute).Unix(),
		"exp": now.Add(-30 * time.Second).Unix(),
	})
	claims, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("verify expired within skew: %v", err)
	}
	if claims.Subject != "u" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestVerifyUnknownKID(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newJWKSServer(t, "kid-1", &key.PublicKey)
	defer srv.Close()
	v, _ := NewVerifier(VerifierConfig{Issuer: "https://i", Audience: "a", JWKSURL: srv.URL})
	tok := signToken(t, key, "kid-other", jwt.MapClaims{
		"iss": "https://i", "aud": "a", "sub": "u", "exp": time.Now().Add(time.Minute).Unix(),
	})
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected unknown kid error")
	}
}

func TestVerifyMissingSub(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newJWKSServer(t, "kid-1", &key.PublicKey)
	defer srv.Close()
	v, _ := NewVerifier(VerifierConfig{Issuer: "https://i", Audience: "a", JWKSURL: srv.URL})
	tok := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": "https://i", "aud": "a", "exp": time.Now().Add(time.Minute).Unix(),
	})
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected missing-sub error")
	}
}

func TestVerifyHS256Rejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newJWKSServer(t, "kid-1", &key.PublicKey)
	defer srv.Close()
	v, _ := NewVerifier(VerifierConfig{Issuer: "https://i", Audience: "a", JWKSURL: srv.URL})
	hsTok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "https://i", "aud": "a", "sub": "u", "exp": time.Now().Add(time.Minute).Unix(),
	})
	hsTok.Header["kid"] = "kid-1"
	raw, _ := hsTok.SignedString([]byte("hs256-secret-32-bytes-xxxxxxxxxxxxxxxx"))
	if _, err := v.Verify(context.Background(), raw); err == nil {
		t.Fatal("expected HS256 to be rejected")
	}
}

func TestVerifyEmptyToken(t *testing.T) {
	v, _ := NewVerifier(VerifierConfig{Issuer: "https://i", Audience: "a", JWKSURL: "https://x"})
	if _, err := v.Verify(context.Background(), "  "); err != ErrInvalidToken {
		t.Fatalf("want ErrInvalidToken, got %v", err)
	}
}
