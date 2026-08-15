package interactiveauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kombifyio/go-common/oidcclient"
)

// Device grant errors.
var (
	ErrDeviceStart   = errors.New("interactiveauth: device authorization start failed")
	ErrDeviceExpired = errors.New("interactiveauth: device code expired")
)

// DeviceGrantConfig configures the RFC 8628 device authorization flow.
type DeviceGrantConfig struct {
	// Provider supplies the token endpoint, client id, and scopes.
	Provider *oidcclient.Provider
	// DeviceAuthorizationURL defaults to `<issuer>/oauth/device/code`
	// (the Auth0 and generic convention).
	DeviceAuthorizationURL string
	// Audience is passed to the device authorization request when set.
	Audience string
	// Prompt displays the user code and verification URI. Required.
	Prompt func(userCode, verificationURI, verificationURIComplete string)
	// Timeout bounds the whole interaction. Defaults to the server-provided
	// expires_in (capped at 15 minutes) when zero.
	Timeout time.Duration
	// PollInterval overrides the server-provided polling interval when
	// positive. RFC 8628 slow_down responses still extend it.
	PollInterval time.Duration
	// HTTPClient defaults to a 30 s per-request timeout client.
	HTTPClient *http.Client
}

// slowDownStep is the RFC 8628 section 3.5 interval increment. Overridable in
// tests only.
var slowDownStep = 5 * time.Second

type deviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

type tokenError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// DeviceGrant runs the full RFC 8628 flow: it requests a device code,
// prompts the user with the verification URI, and polls the token endpoint —
// honoring `authorization_pending` and `slow_down` — until approval, denial,
// expiry, or timeout.
func DeviceGrant(ctx context.Context, cfg DeviceGrantConfig) (*oidcclient.CodeExchangeResult, error) {
	if cfg.Provider == nil || cfg.Prompt == nil {
		return nil, fmt.Errorf("%w: provider and Prompt are required", ErrInvalidConfig)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	startURL := strings.TrimSpace(cfg.DeviceAuthorizationURL)
	if startURL == "" {
		startURL = strings.TrimRight(cfg.Provider.Issuer(), "/") + "/oauth/device/code"
	}

	auth, err := startDeviceAuthorization(ctx, client, startURL, cfg)
	if err != nil {
		return nil, err
	}
	cfg.Prompt(auth.UserCode, auth.VerificationURI, auth.VerificationURIComplete)

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Minute
		if auth.ExpiresIn > 0 && time.Duration(auth.ExpiresIn)*time.Second < timeout {
			timeout = time.Duration(auth.ExpiresIn) * time.Second
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	interval := time.Duration(auth.Interval) * time.Second
	if cfg.PollInterval > 0 {
		interval = cfg.PollInterval
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return pollUntilComplete(ctx, client, cfg.Provider, auth.DeviceCode, interval)
}

// pollUntilComplete runs the RFC 8628 polling loop until a terminal outcome.
func pollUntilComplete(ctx context.Context, client *http.Client, provider *oidcclient.Provider, deviceCode string, interval time.Duration) (*oidcclient.CodeExchangeResult, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: %v", ErrFlowTimeout, ctx.Err())
		case <-time.After(interval):
		}
		result, slowDown, err := pollDeviceToken(ctx, client, provider, deviceCode)
		if err != nil {
			return nil, err
		}
		if result != nil {
			return result, nil
		}
		if slowDown {
			interval += slowDownStep
		}
	}
}

func startDeviceAuthorization(ctx context.Context, client *http.Client, startURL string, cfg DeviceGrantConfig) (*deviceAuthorization, error) {
	values := url.Values{}
	values.Set("client_id", cfg.Provider.ClientID())
	if scopes := cfg.Provider.Scopes(); len(scopes) > 0 {
		values.Set("scope", strings.Join(scopes, " "))
	}
	if cfg.Audience != "" {
		values.Set("audience", cfg.Audience)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, startURL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDeviceStart, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDeviceStart, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: status %d", ErrDeviceStart, resp.StatusCode)
	}
	auth := &deviceAuthorization{}
	if err := json.Unmarshal(body, auth); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrDeviceStart, err)
	}
	if auth.DeviceCode == "" || auth.UserCode == "" || auth.VerificationURI == "" {
		return nil, fmt.Errorf("%w: incomplete device authorization response", ErrDeviceStart)
	}
	return auth, nil
}

// pollDeviceToken performs one token poll. It returns (result, false, nil) on
// success, (nil, slowDown, nil) when polling must continue, and a terminal
// error otherwise. Unlike the authorization-code exchange, the device grant
// does not require an id_token: CLI tool tokens are access-token-centric;
// callers needing OIDC identity request the openid scope and verify the
// returned id_token themselves.
func pollDeviceToken(ctx context.Context, client *http.Client, provider *oidcclient.Provider, deviceCode string) (*oidcclient.CodeExchangeResult, bool, error) {
	values := url.Values{}
	values.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	values.Set("device_code", deviceCode)
	values.Set("client_id", provider.ClientID())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.TokenURL(), strings.NewReader(values.Encode()))
	if err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrCallback, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrCallback, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		result := &oidcclient.CodeExchangeResult{}
		if err := json.Unmarshal(body, result); err != nil {
			return nil, false, fmt.Errorf("%w: decode token response: %v", ErrCallback, err)
		}
		if result.AccessToken == "" && result.IDToken == "" {
			return nil, false, fmt.Errorf("%w: token response carried no token", ErrCallback)
		}
		return result, false, nil
	}

	failure := &tokenError{}
	_ = json.Unmarshal(body, failure)
	switch failure.Error {
	case "authorization_pending":
		return nil, false, nil
	case "slow_down":
		// RFC 8628 section 3.5: increase the polling interval by 5 seconds.
		return nil, true, nil
	case oauthErrorAccessDenied:
		return nil, false, fmt.Errorf("%w: %s", ErrAccessDenied, failure.ErrorDescription)
	case "expired_token":
		return nil, false, fmt.Errorf("%w: %s", ErrDeviceExpired, failure.ErrorDescription)
	default:
		return nil, false, fmt.Errorf("%w: status %d error %q", ErrCallback, resp.StatusCode, failure.Error)
	}
}
