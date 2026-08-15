package oidcclient

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Defaults for JWKS cache behaviour. Min interval throttles upstream JWKS
// hits when a token references an unknown KID (could be attacker-driven).
// Max interval forces periodic refresh even if no cache miss occurs.
const (
	DefaultJWKSRefreshMin = 30 * time.Second
	DefaultJWKSRefreshMax = 15 * time.Minute
	DefaultHTTPTimeout    = 5 * time.Second
)

// Errors returned by Verify.
var (
	ErrInvalidToken     = errors.New("oidcclient: invalid token")
	ErrUnknownKID       = errors.New("oidcclient: unknown key id")
	ErrUnsupportedAlg   = errors.New("oidcclient: unsupported signing algorithm")
	ErrIssuerMismatch   = errors.New("oidcclient: issuer mismatch")
	ErrAudienceMismatch = errors.New("oidcclient: audience mismatch")
	ErrTokenExpired     = errors.New("oidcclient: token expired")
	ErrTokenNotYetValid = errors.New("oidcclient: token not yet valid")
	ErrJWKSFetchFailed  = errors.New("oidcclient: jwks fetch failed")
	ErrConfigInvalid    = errors.New("oidcclient: configuration invalid")
)

// VerifierConfig configures a [Verifier].
type VerifierConfig struct {
	Issuer         string
	Audience       string
	JWKSURL        string
	HTTPClient     *http.Client
	JWKSRefreshMin time.Duration
	JWKSRefreshMax time.Duration
	ClockSkew      time.Duration
}

// Claims is the verified subset of an ID token. Provider-specific claims can
// be re-decoded by callers from [Claims.Raw].
type Claims struct {
	Subject  string                 `json:"sub"`
	Issuer   string                 `json:"iss"`
	Audience []string               `json:"aud"`
	Email    string                 `json:"email,omitempty"`
	Name     string                 `json:"name,omitempty"`
	IssuedAt int64                  `json:"iat,omitempty"`
	Expires  int64                  `json:"exp,omitempty"`
	Raw      map[string]interface{} `json:"-"`
}

// Verifier verifies OIDC ID tokens issued by a single issuer.
type Verifier struct {
	cfg    VerifierConfig
	client *http.Client

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

// NewVerifier constructs a Verifier and validates required config.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if strings.TrimSpace(cfg.Issuer) == "" {
		return nil, fmt.Errorf("%w: issuer is required", ErrConfigInvalid)
	}
	if strings.TrimSpace(cfg.Audience) == "" {
		return nil, fmt.Errorf("%w: audience is required", ErrConfigInvalid)
	}
	if strings.TrimSpace(cfg.JWKSURL) == "" {
		return nil, fmt.Errorf("%w: jwks_url is required", ErrConfigInvalid)
	}
	if cfg.JWKSRefreshMin <= 0 {
		cfg.JWKSRefreshMin = DefaultJWKSRefreshMin
	}
	if cfg.JWKSRefreshMax <= 0 {
		cfg.JWKSRefreshMax = DefaultJWKSRefreshMax
	}
	if cfg.JWKSRefreshMax < cfg.JWKSRefreshMin {
		return nil, fmt.Errorf("%w: jwks_refresh_max < jwks_refresh_min", ErrConfigInvalid)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: DefaultHTTPTimeout}
	}
	return &Verifier{cfg: cfg, client: client, keys: map[string]*rsa.PublicKey{}}, nil
}

// Verify parses and validates the given raw ID token. On success the returned
// [Claims] are guaranteed to match issuer + audience and to be within
// exp/nbf bounds (with [VerifierConfig.ClockSkew] tolerance).
func (v *Verifier) Verify(ctx context.Context, rawToken string) (*Claims, error) {
	if strings.TrimSpace(rawToken) == "" {
		return nil, ErrInvalidToken
	}
	parserOptions := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuedAt(),
	}
	if v.cfg.ClockSkew > 0 {
		parserOptions = append(parserOptions, jwt.WithLeeway(v.cfg.ClockSkew))
	}
	parser := jwt.NewParser(parserOptions...)
	parsed, err := parser.ParseWithClaims(rawToken, jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != "RS256" {
			return nil, ErrUnsupportedAlg
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("%w: missing kid header", ErrInvalidToken)
		}
		key, err := v.keyFor(ctx, kid)
		if err != nil {
			return nil, err
		}
		return key, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) || errors.Is(err, jwt.ErrTokenUsedBeforeIssued) {
			return nil, ErrTokenNotYetValid
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	mc, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || !parsed.Valid {
		return nil, ErrInvalidToken
	}
	return v.validateClaims(mc)
}

func (v *Verifier) validateClaims(mc jwt.MapClaims) (*Claims, error) {
	iss, _ := mc["iss"].(string)
	if iss != v.cfg.Issuer {
		return nil, ErrIssuerMismatch
	}
	if !audienceMatches(mc["aud"], v.cfg.Audience) {
		return nil, ErrAudienceMismatch
	}
	out := &Claims{Issuer: iss, Raw: map[string]interface{}(mc)}
	out.Subject, _ = mc["sub"].(string)
	if out.Subject == "" {
		return nil, fmt.Errorf("%w: missing sub", ErrInvalidToken)
	}
	out.Email, _ = mc["email"].(string)
	out.Name, _ = mc["name"].(string)
	if iat, ok := mc["iat"].(float64); ok {
		out.IssuedAt = int64(iat)
	}
	if exp, ok := mc["exp"].(float64); ok {
		out.Expires = int64(exp)
	}
	switch a := mc["aud"].(type) {
	case string:
		out.Audience = []string{a}
	case []interface{}:
		for _, x := range a {
			if s, ok := x.(string); ok {
				out.Audience = append(out.Audience, s)
			}
		}
	}
	return out, nil
}

func audienceMatches(raw interface{}, expected string) bool {
	switch a := raw.(type) {
	case string:
		return a == expected
	case []interface{}:
		for _, x := range a {
			if s, ok := x.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

func (v *Verifier) keyFor(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key, ok := v.keys[kid]
	age := time.Since(v.fetchedAt)
	v.mu.RUnlock()
	if ok && age < v.cfg.JWKSRefreshMax {
		return key, nil
	}
	// Either unknown KID or cache stale → refresh, but throttle.
	if !ok && age < v.cfg.JWKSRefreshMin {
		return nil, ErrUnknownKID
	}
	if err := v.refresh(ctx); err != nil {
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	key, ok = v.keys[kid]
	if !ok {
		return nil, ErrUnknownKID
	}
	return key, nil
}

func (v *Verifier) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSFetchFailed, err)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSFetchFailed, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%w: status %d", ErrJWKSFetchFailed, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSFetchFailed, err)
	}
	var doc jwksDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSFetchFailed, err)
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		pk, err := k.toRSA()
		if err != nil {
			continue
		}
		if k.Kid == "" {
			continue
		}
		keys[k.Kid] = pk
	}
	v.mu.Lock()
	v.keys = keys
	v.fetchedAt = time.Now()
	v.mu.Unlock()
	return nil
}

type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (k jwk) toRSA() (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return nil, errors.New("oidcclient: jwk exponent overflow")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e.Int64())}, nil
}
