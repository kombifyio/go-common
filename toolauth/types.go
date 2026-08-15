// Package toolauth provides client-side authentication for kombify desktop tools.
//
// Desktop tools (SpeechKit, etc.) use this package to authenticate against the
// kombify Cloud platform via API key or device code flow. It handles token
// storage (OS credential store or encrypted file fallback), automatic token
// refresh, entitlement checking with caching, and batched usage reporting.
package toolauth

import "time"

// TokenPair holds the access and refresh tokens issued by the platform.
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	UserID       string    `json:"user_id"`
}

// IsExpired reports whether the access token has expired.
// A 30-second buffer is applied to avoid using a token that is about to expire.
func (t *TokenPair) IsExpired() bool {
	return time.Now().After(t.ExpiresAt.Add(-30 * time.Second))
}

// AuthResult is the outcome of a successful authentication attempt.
type AuthResult struct {
	Token        TokenPair    `json:"token"`
	Entitlements *Entitlements `json:"entitlements,omitempty"`
}

// Entitlements describes what features a tool license grants.
type Entitlements struct {
	Tool      string         `json:"tool"`
	Features  map[string]any `json:"features,omitempty"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
}

// DeviceCodeResponse is returned when initiating the device code auth flow.
// The user must visit VerificationURI and enter UserCode to authorize the device.
type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// UsageEvent represents a single usage metric to be reported to the platform.
type UsageEvent struct {
	Metric string    `json:"metric"`
	Value  float64   `json:"value"`
	At     time.Time `json:"at"`
}
