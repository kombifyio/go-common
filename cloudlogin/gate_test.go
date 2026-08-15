package cloudlogin

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newEd25519PEM(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return priv, string(pemBytes)
}

func signToken(t *testing.T, priv ed25519.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	raw, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestEvaluateSaaSAlwaysEnabled(t *testing.T) {
	r := Evaluate(Options{IsSaaS: true})
	if !r.Enabled || r.Reason != "saas_mode" {
		t.Fatalf("result=%+v", r)
	}
}

func TestEvaluateUnsupportedMode(t *testing.T) {
	r := Evaluate(Options{})
	if r.Enabled || r.Reason != "unsupported_mode" {
		t.Fatalf("result=%+v", r)
	}
}

func TestEvaluateSelfHostedHappyPath(t *testing.T) {
	priv, pemKey := newEd25519PEM(t)
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":     "instance-42",
		"feature": FeatureKey,
		"origin":  "https://techstack.example.com",
		"iss":     "kombify-cloud",
		"aud":     []string{DefaultAudience},
		"iat":     now.Unix(),
		"exp":     now.Add(24 * time.Hour).Unix(),
	}
	token := signToken(t, priv, claims)

	r := Evaluate(Options{
		IsSelfHosted:   true,
		PublicOrigin:   "https://techstack.example.com",
		Token:          token,
		PublicKeyPEM:   pemKey,
		ExpectedIssuer: "kombify-cloud",
		Now:            func() time.Time { return now },
	})
	if !r.Enabled || r.Subject != "instance-42" || r.Reason != "enrollment_valid" {
		t.Fatalf("result=%+v", r)
	}
}

func TestEvaluateSelfHostedFailures(t *testing.T) {
	priv, pemKey := newEd25519PEM(t)
	now := time.Now()
	mk := func(overrides jwt.MapClaims) string {
		base := jwt.MapClaims{
			"sub":     "i-1",
			"feature": FeatureKey,
			"origin":  "https://app.example.com",
			"aud":     []string{DefaultAudience},
			"iat":     now.Unix(),
			"exp":     now.Add(time.Hour).Unix(),
		}
		for k, v := range overrides {
			base[k] = v
		}
		return signToken(t, priv, base)
	}

	cases := []struct {
		name string
		opts Options
		want string
	}{
		{"missing origin", Options{IsSelfHosted: true, Token: mk(nil), PublicKeyPEM: pemKey}, "public_origin_missing"},
		{"missing token", Options{IsSelfHosted: true, PublicOrigin: "https://app.example.com", PublicKeyPEM: pemKey}, "token_missing"},
		{"missing key", Options{IsSelfHosted: true, PublicOrigin: "https://app.example.com", Token: mk(nil)}, "public_key_missing"},
		{"bad key pem", Options{IsSelfHosted: true, PublicOrigin: "https://app.example.com", Token: mk(nil), PublicKeyPEM: "not-a-pem"}, "public_key_invalid"},
		{"feature mismatch", Options{IsSelfHosted: true, PublicOrigin: "https://app.example.com", Token: mk(jwt.MapClaims{"feature": "other"}), PublicKeyPEM: pemKey, Now: func() time.Time { return now }}, "feature_mismatch"},
		{"audience mismatch", Options{IsSelfHosted: true, PublicOrigin: "https://app.example.com", Token: mk(jwt.MapClaims{"aud": []string{"other"}}), PublicKeyPEM: pemKey, Now: func() time.Time { return now }}, "audience_mismatch"},
		{"issuer mismatch", Options{IsSelfHosted: true, PublicOrigin: "https://app.example.com", Token: mk(jwt.MapClaims{"iss": "wrong"}), PublicKeyPEM: pemKey, ExpectedIssuer: "right", Now: func() time.Time { return now }}, "issuer_mismatch"},
		{"origin mismatch", Options{IsSelfHosted: true, PublicOrigin: "https://app.example.com", Token: mk(jwt.MapClaims{"origin": "https://other.com"}), PublicKeyPEM: pemKey, Now: func() time.Time { return now }}, "origin_mismatch"},
		{"subject missing", Options{IsSelfHosted: true, PublicOrigin: "https://app.example.com", Token: mk(jwt.MapClaims{"sub": ""}), PublicKeyPEM: pemKey, Now: func() time.Time { return now }}, "subject_missing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Evaluate(c.opts)
			if r.Enabled || r.Reason != c.want {
				t.Fatalf("got %+v want reason=%q", r, c.want)
			}
		})
	}
}

func TestEvaluateExpiredToken(t *testing.T) {
	priv, pemKey := newEd25519PEM(t)
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":     "i-1",
		"feature": FeatureKey,
		"origin":  "https://app.example.com",
		"aud":     []string{DefaultAudience},
		"iat":     now.Add(-2 * time.Hour).Unix(),
		"exp":     now.Add(-time.Hour).Unix(),
	}
	token := signToken(t, priv, claims)
	r := Evaluate(Options{
		IsSelfHosted: true,
		PublicOrigin: "https://app.example.com",
		Token:        token,
		PublicKeyPEM: pemKey,
		Now:          func() time.Time { return now },
	})
	if r.Enabled || r.Reason != "token_invalid" {
		t.Fatalf("result=%+v", r)
	}
}

func TestNormalizeOrigin(t *testing.T) {
	cases := map[string]string{
		"https://app.example.com":  "https://app.example.com",
		"https://app.example.com/": "https://app.example.com",
		" http://x  ":              "http://x",
		"":                         "",
		"not a url":                "",
		"https://x/path":           "",
	}
	for in, want := range cases {
		if got := normalizeOrigin(in); got != want {
			t.Errorf("normalizeOrigin(%q) = %q want %q", in, got, want)
		}
	}
}

func TestOptionsFromEnvPrefixFallback(t *testing.T) {
	t.Setenv("KOMBIFY_DEPLOYMENT_MODE", "saas")
	t.Setenv("KOMBIFY_PUBLIC_ORIGIN", "https://x")
	opts := OptionsFromEnv("")
	if !opts.IsSaaS {
		t.Fatal("expected SaaS")
	}
	if opts.PublicOrigin != "https://x" {
		t.Fatalf("origin=%q", opts.PublicOrigin)
	}
}

func TestOptionsFromEnvCustomPrefix(t *testing.T) {
	t.Setenv("MYAPP_DEPLOYMENT_MODE", "selfhosted")
	t.Setenv("MYAPP_SELFHOSTED_CLOUD_LOGIN_TOKEN", "tok")
	t.Setenv("MYAPP_SELFHOSTED_CLOUD_LOGIN_PUBLIC_KEY", "key")
	opts := OptionsFromEnv("MYAPP")
	if !opts.IsSelfHosted || opts.IsSaaS {
		t.Fatalf("flags=%+v", opts)
	}
	if opts.Token != "tok" || !strings.Contains(opts.PublicKeyPEM, "key") {
		t.Fatalf("opts=%+v", opts)
	}
}
