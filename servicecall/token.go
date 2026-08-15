package servicecall

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Token-validation errors. Kept package-level so callers can type-switch.
var (
	ErrBadToken      = errors.New("servicecall: malformed token")
	ErrBadSignature  = errors.New("servicecall: invalid signature")
	ErrExpired       = errors.New("servicecall: token expired")
	ErrNotYetValid   = errors.New("servicecall: token not yet valid")
	ErrEmptySecret   = errors.New("servicecall: empty signing secret")
	ErrWrongAudience = errors.New("servicecall: wrong audience")
	ErrCallerDenied  = errors.New("servicecall: caller not in allowlist")
)

// Fixed header bytes for HS256 JWT. Matches the standard `{"alg":"HS256","typ":"JWT"}`.
// We emit the same bytes every time so the encoded prefix is deterministic and
// we don't need to parse the header on verify.
var jwtHeader = []byte(`{"alg":"HS256","typ":"JWT"}`)

// IssueToken builds a signed service-call token from cfg and the supplied
// target/obo/requestID. cfg.ServiceName and cfg.Secret must be set.
func IssueToken(cfg Config, target string, obo *OnBehalfOf, requestID string) (string, error) {
	if cfg.Secret == "" {
		return "", ErrEmptySecret
	}
	ttl := cfg.TokenTTL
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}
	now := time.Now()
	claims := Claims{
		Iss:        "kombify-" + cfg.ServiceName,
		Aud:        "kombify-" + target,
		Iat:        now.Unix(),
		Exp:        now.Add(ttl).Unix(),
		Svc:        cfg.ServiceName,
		OnBehalfOf: obo,
		RequestID:  requestID,
	}
	return signClaims(claims, cfg.Secret)
}

// VerifyToken parses and validates token against primary (and optionally
// secretNext during rotation). Returns the decoded claims on success.
// Does NOT enforce audience or caller policy — that is the middleware's job.
func VerifyToken(token, primary, next string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrBadToken
	}
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrBadToken
	}
	if !verifyHMAC(signingInput, sig, primary) && !verifyHMAC(signingInput, sig, next) {
		return nil, ErrBadSignature
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrBadToken
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, ErrBadToken
	}
	now := time.Now()
	if c.Exp > 0 && now.Unix() > c.Exp {
		return nil, ErrExpired
	}
	if c.Iat > 0 && now.Add(clockSkewTolerance).Unix() < c.Iat {
		return nil, ErrNotYetValid
	}
	return &c, nil
}

func signClaims(claims Claims, secret string) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(jwtHeader) +
		"." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func verifyHMAC(signingInput string, sig []byte, secret string) bool {
	if secret == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	return hmac.Equal(mac.Sum(nil), sig)
}
