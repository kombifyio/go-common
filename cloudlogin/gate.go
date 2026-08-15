// Package cloudlogin implements the fail-closed enrollment-token gate for
// kombify Cloud login on a self-hosted instance.
//
// The gate is "fail-closed" by design: SaaS deployments expose Cloud login
// unconditionally; self-hosted deployments must produce a signed enrollment
// token that proves the operator has explicitly opted into talking to
// kombify Cloud. Without the token (or with any signature/origin/audience
// mismatch) the gate returns Enabled=false plus a machine-readable Reason
// suitable for surfacing in /readyz, audit logs, or admin telemetry.
//
// Donor: kombify-Techstack/pkg/cloudlogin (lifted 2026-05-03 with the
// techstack-specific config.DeploymentMode dependency replaced by simple
// IsSaaS / IsSelfHosted booleans).
package cloudlogin

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// FeatureKey is the value the enrollment token must carry in its `feature`
// claim. Mismatched tokens (e.g. issued for a different kombify product) are
// rejected with Reason "feature_mismatch".
const FeatureKey = "cloud_login"

// DefaultAudience is the audience claim used when [Options.ExpectedAudience]
// is empty. Consumers SHOULD set their own product-specific audience (e.g.
// "kombify-techstack:selfhosted-cloud-login").
const DefaultAudience = "kombify:selfhosted-cloud-login"

// EnvPrefix is the default env-var prefix used by [OptionsFromEnv].
const EnvPrefix = "KOMBIFY"

// Result is the fail-closed outcome of the self-hosted cloud-login gate.
type Result struct {
	Enabled bool
	Reason  string
	Subject string
}

// Options configures evaluation of the self-hosted cloud-login gate.
type Options struct {
	// IsSaaS short-circuits the gate to Enabled=true. Mutually exclusive
	// with IsSelfHosted; if neither is set the gate refuses with reason
	// "unsupported_mode".
	IsSaaS bool
	// IsSelfHosted gates token verification.
	IsSelfHosted bool
	// PublicOrigin is the canonical https://… origin of the local instance,
	// matched against the enrollment token's `origin` claim.
	PublicOrigin string
	// Token is the signed enrollment JWT issued by kombify Cloud.
	Token string
	// PublicKeyPEM is the PEM-encoded RSA / ECDSA / Ed25519 public key (or
	// X.509 certificate) used to verify Token.
	PublicKeyPEM string
	// ExpectedIssuer optionally constrains the token's `iss` claim.
	ExpectedIssuer string
	// ExpectedAudience overrides [DefaultAudience].
	ExpectedAudience string
	// Now is injectable for tests.
	Now func() time.Time
}

type enrollmentClaims struct {
	Feature string `json:"feature,omitempty"`
	Origin  string `json:"origin,omitempty"`
	jwt.RegisteredClaims
}

// OptionsFromEnv builds gate options from environment variables under the
// given prefix. The empty prefix falls back to [EnvPrefix].
//
// Read variables (with prefix "X"):
//
//	X_DEPLOYMENT_MODE                 — "saas" | "selfhosted"
//	X_PUBLIC_ORIGIN                   — canonical origin (also PUBLIC_ORIGIN, APP_URL)
//	X_SELFHOSTED_CLOUD_LOGIN_TOKEN    — signed enrollment JWT
//	X_SELFHOSTED_CLOUD_LOGIN_PUBLIC_KEY — PEM key
//	X_SELFHOSTED_CLOUD_LOGIN_ISSUER   — optional iss constraint
//	X_SELFHOSTED_CLOUD_LOGIN_AUDIENCE — optional aud override
func OptionsFromEnv(prefix string) Options {
	if prefix == "" {
		prefix = EnvPrefix
	}
	mode := strings.ToLower(strings.TrimSpace(os.Getenv(prefix + "_DEPLOYMENT_MODE")))
	return Options{
		IsSaaS:           mode == "saas",
		IsSelfHosted:     mode == "selfhosted" || mode == "self-hosted",
		PublicOrigin:     publicOriginFromEnv(prefix),
		Token:            strings.TrimSpace(os.Getenv(prefix + "_SELFHOSTED_CLOUD_LOGIN_TOKEN")),
		PublicKeyPEM:     strings.TrimSpace(os.Getenv(prefix + "_SELFHOSTED_CLOUD_LOGIN_PUBLIC_KEY")),
		ExpectedIssuer:   strings.TrimSpace(os.Getenv(prefix + "_SELFHOSTED_CLOUD_LOGIN_ISSUER")),
		ExpectedAudience: strings.TrimSpace(os.Getenv(prefix + "_SELFHOSTED_CLOUD_LOGIN_AUDIENCE")),
	}
}

// Evaluate returns whether kombify Cloud login may be exposed. SaaS mode is
// always allowed. Self-hosted mode requires a signed enrollment token bound
// to the instance's public origin.
func Evaluate(opts Options) Result {
	if opts.IsSaaS {
		return Result{Enabled: true, Reason: "saas_mode"}
	}
	if !opts.IsSelfHosted {
		return Result{Reason: "unsupported_mode"}
	}

	expectedOrigin := normalizeOrigin(opts.PublicOrigin)
	if expectedOrigin == "" {
		return Result{Reason: "public_origin_missing"}
	}
	if strings.TrimSpace(opts.Token) == "" {
		return Result{Reason: "token_missing"}
	}
	if strings.TrimSpace(opts.PublicKeyPEM) == "" {
		return Result{Reason: "public_key_missing"}
	}

	publicKey, validMethods, err := parsePublicKey(opts.PublicKeyPEM)
	if err != nil {
		return Result{Reason: "public_key_invalid"}
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}
	audience := strings.TrimSpace(opts.ExpectedAudience)
	if audience == "" {
		audience = DefaultAudience
	}
	claims := &enrollmentClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods(validMethods),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(time.Minute),
		jwt.WithTimeFunc(now),
	)
	token, err := parser.ParseWithClaims(strings.TrimSpace(opts.Token), claims, func(token *jwt.Token) (any, error) {
		return publicKey, nil
	})
	if err != nil || token == nil || !token.Valid {
		return Result{Reason: "token_invalid"}
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return Result{Reason: "subject_missing"}
	}
	if strings.TrimSpace(claims.Feature) != FeatureKey {
		return Result{Reason: "feature_mismatch"}
	}
	if !hasAudience(claims.Audience, audience) {
		return Result{Reason: "audience_mismatch"}
	}
	if expectedIssuer := strings.TrimSpace(opts.ExpectedIssuer); expectedIssuer != "" && strings.TrimSpace(claims.Issuer) != expectedIssuer {
		return Result{Reason: "issuer_mismatch"}
	}
	if normalizeOrigin(claims.Origin) != expectedOrigin {
		return Result{Reason: "origin_mismatch"}
	}

	return Result{Enabled: true, Reason: "enrollment_valid", Subject: claims.Subject}
}

func hasAudience(audiences []string, want string) bool {
	for _, audience := range audiences {
		if strings.TrimSpace(audience) == want {
			return true
		}
	}
	return false
}

func parsePublicKey(raw string) (any, []string, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(raw)))
	if block == nil {
		return nil, nil, fmt.Errorf("cloudlogin: invalid PEM")
	}
	switch block.Type {
	case "PUBLIC KEY":
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		return supportedKey(parsed)
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		return supportedKey(cert.PublicKey)
	default:
		return nil, nil, fmt.Errorf("cloudlogin: unsupported PEM block %q", block.Type)
	}
}

func supportedKey(key any) (any, []string, error) {
	switch typed := key.(type) {
	case ed25519.PublicKey:
		return typed, []string{jwt.SigningMethodEdDSA.Alg()}, nil
	case *rsa.PublicKey:
		return typed, []string{
			jwt.SigningMethodRS256.Alg(),
			jwt.SigningMethodRS384.Alg(),
			jwt.SigningMethodRS512.Alg(),
			jwt.SigningMethodPS256.Alg(),
			jwt.SigningMethodPS384.Alg(),
			jwt.SigningMethodPS512.Alg(),
		}, nil
	case *ecdsa.PublicKey:
		return typed, []string{
			jwt.SigningMethodES256.Alg(),
			jwt.SigningMethodES384.Alg(),
			jwt.SigningMethodES512.Alg(),
		}, nil
	default:
		return nil, nil, fmt.Errorf("cloudlogin: unsupported key type %T", key)
	}
}

func publicOriginFromEnv(prefix string) string {
	keys := []string{
		prefix + "_PUBLIC_ORIGIN",
		"PUBLIC_ORIGIN",
		"APP_PUBLIC_ORIGIN",
		"APP_URL",
	}
	for _, key := range keys {
		if value := normalizeOrigin(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func normalizeOrigin(raw string) string {
	trimmed := strings.TrimSpace(strings.TrimSuffix(raw, "/"))
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || (parsed.Path != "" && parsed.Path != "/") {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}
