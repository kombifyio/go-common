package toolauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config configures the toolauth Client.
type Config struct {
	// BaseURL is the kombify API base URL (e.g. "https://api.kombify.io").
	BaseURL string
	// ToolName identifies the tool (e.g. "speechkit").
	ToolName string
	// ToolVersion is the semantic version of the tool (e.g. "0.1.0").
	ToolVersion string
	// TokenStore provides persistent token storage. If nil, the platform
	// default is used (Windows Credential Manager or encrypted file).
	TokenStore TokenStore
	// HTTPClient is an optional custom HTTP client. If nil, a default
	// client with a 30-second timeout is used.
	HTTPClient *http.Client
}

// Client authenticates desktop tools against the kombify Cloud platform.
// It manages token lifecycle (obtain, refresh, store) and provides
// access to entitlements and usage reporting.
//
// Client is safe for concurrent use.
type Client struct {
	cfg        Config
	httpClient *http.Client
	store      TokenStore

	mu    sync.RWMutex
	token *TokenPair

	entMu        sync.RWMutex
	entitlements *Entitlements
	entFetchedAt time.Time

	usageMu  sync.Mutex
	usageBuf []UsageEvent
}

const entitlementCacheTTL = 24 * time.Hour

// New creates a new toolauth Client. It attempts to load a previously stored
// token from the token store. An error is returned only if the configuration
// is invalid; a missing stored token is not an error.
func New(cfg Config) (*Client, error) {
	baseURL, err := validateBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	if cfg.ToolName == "" {
		return nil, fmt.Errorf("toolauth: ToolName is required")
	}

	store := cfg.TokenStore
	if store == nil {
		store = defaultTokenStore()
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	c := &Client{
		cfg:        cfg,
		httpClient: httpClient,
		store:      store,
	}
	c.cfg.BaseURL = baseURL

	// Best-effort load of previously stored token.
	if token, err := store.Load(cfg.ToolName); err == nil && token != nil {
		c.token = token
	}

	return c, nil
}

func validateBaseURL(raw string) (string, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(raw), "/")
	if baseURL == "" {
		return "", fmt.Errorf("toolauth: BaseURL is required")
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("toolauth: BaseURL must be an absolute HTTP(S) URL without userinfo, query, or fragment")
	}
	if u.Scheme == "https" {
		return baseURL, nil
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	ip := net.ParseIP(host)
	if u.Scheme == "http" && (host == "localhost" || (ip != nil && ip.IsLoopback())) {
		return baseURL, nil
	}
	return "", fmt.Errorf("toolauth: BaseURL must use HTTPS; HTTP is allowed only for loopback development")
}

// authVerifyRequest is the request body for API key authentication.
type authVerifyRequest struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
}

// authResponse is the common response from auth endpoints.
type authResponse struct {
	Token        TokenPair     `json:"token"`
	Entitlements *Entitlements `json:"entitlements,omitempty"`
}

// AuthenticateWithAPIKey authenticates using a pre-provisioned API key.
// On success the token is persisted to the token store.
func (c *Client) AuthenticateWithAPIKey(ctx context.Context, apiKey string) (*AuthResult, error) {
	body, err := json.Marshal(authVerifyRequest{
		Tool:    c.cfg.ToolName,
		Version: c.cfg.ToolVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("toolauth: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+"/api/v1/tools/auth/verify", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("toolauth: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	c.setUserAgent(req)

	var resp authResponse
	if err := c.doJSON(req, &resp); err != nil {
		return nil, fmt.Errorf("toolauth: API key auth: %w", err)
	}

	c.storeToken(&resp.Token)
	c.cacheEntitlements(resp.Entitlements)

	return &AuthResult{
		Token:        resp.Token,
		Entitlements: resp.Entitlements,
	}, nil
}

// deviceCodeRequest is the request body for starting the device code flow.
type deviceCodeRequest struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
}

// StartDeviceCodeFlow initiates the OAuth 2.0 device authorization flow.
// The caller should display VerificationURI and UserCode to the user, then
// poll with PollDeviceCode.
func (c *Client) StartDeviceCodeFlow(ctx context.Context) (*DeviceCodeResponse, error) {
	body, err := json.Marshal(deviceCodeRequest{
		Tool:    c.cfg.ToolName,
		Version: c.cfg.ToolVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("toolauth: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+"/api/v1/tools/auth/device-code", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("toolauth: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.setUserAgent(req)

	var resp DeviceCodeResponse
	if err := c.doJSON(req, &resp); err != nil {
		return nil, fmt.Errorf("toolauth: start device code flow: %w", err)
	}

	return &resp, nil
}

// deviceCodePollRequest is the request body for polling the device code.
type deviceCodePollRequest struct {
	DeviceCode string `json:"device_code"`
	Tool       string `json:"tool"`
}

// PollDeviceCode polls the platform to check whether the user has completed
// the device code authorization. Returns ErrAuthorizationPending if the user
// has not yet authorized, or ErrDeviceCodeExpired if the code has expired.
func (c *Client) PollDeviceCode(ctx context.Context, deviceCode string) (*AuthResult, error) {
	body, err := json.Marshal(deviceCodePollRequest{
		DeviceCode: deviceCode,
		Tool:       c.cfg.ToolName,
	})
	if err != nil {
		return nil, fmt.Errorf("toolauth: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+"/api/v1/tools/auth/device-code/poll", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("toolauth: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.setUserAgent(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("toolauth: poll device code: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Authorization complete.
	case http.StatusAccepted:
		return nil, ErrAuthorizationPending
	case http.StatusGone:
		return nil, ErrDeviceCodeExpired
	default:
		return nil, readAPIError(resp)
	}

	var authResp authResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, fmt.Errorf("toolauth: decode response: %w", err)
	}

	c.storeToken(&authResp.Token)
	c.cacheEntitlements(authResp.Entitlements)

	return &AuthResult{
		Token:        authResp.Token,
		Entitlements: authResp.Entitlements,
	}, nil
}

// GetAccessToken returns a valid access token, refreshing it if necessary.
// Returns an error if the client is not authenticated.
func (c *Client) GetAccessToken(ctx context.Context) (string, error) {
	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	if token == nil {
		return "", ErrNotAuthenticated
	}

	if token.IsExpired() {
		if err := c.refreshToken(ctx); err != nil {
			return "", fmt.Errorf("toolauth: refresh token: %w", err)
		}
		c.mu.RLock()
		token = c.token
		c.mu.RUnlock()
	}

	return token.AccessToken, nil
}

// IsAuthenticated reports whether the client holds a token.
// This does not verify the token is still valid on the server.
func (c *Client) IsAuthenticated() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token != nil
}

// Logout clears the stored token and cached entitlements.
func (c *Client) Logout(_ context.Context) error {
	c.mu.Lock()
	c.token = nil
	c.mu.Unlock()

	c.entMu.Lock()
	c.entitlements = nil
	c.entFetchedAt = time.Time{}
	c.entMu.Unlock()

	if err := c.store.Delete(c.cfg.ToolName); err != nil {
		return fmt.Errorf("toolauth: delete stored token: %w", err)
	}
	return nil
}

// refreshTokenRequest is the request body for token refresh.
type refreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
	Tool         string `json:"tool"`
}

// refreshToken exchanges the refresh token for a new token pair.
func (c *Client) refreshToken(ctx context.Context) error {
	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	if token == nil {
		return ErrNotAuthenticated
	}

	// #nosec G117 -- RefreshToken is the required API wire field and New limits
	// its transport to HTTPS or explicit loopback HTTP.
	body, err := json.Marshal(refreshTokenRequest{
		RefreshToken: token.RefreshToken,
		Tool:         c.cfg.ToolName,
	})
	if err != nil {
		return fmt.Errorf("toolauth: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+"/api/v1/tools/auth/refresh", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("toolauth: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.setUserAgent(req)

	var resp authResponse
	if err := c.doJSON(req, &resp); err != nil {
		return fmt.Errorf("toolauth: refresh: %w", err)
	}

	c.storeToken(&resp.Token)
	return nil
}

// storeToken persists the token both in memory and to the token store.
func (c *Client) storeToken(token *TokenPair) {
	c.mu.Lock()
	c.token = token
	c.mu.Unlock()

	// Best-effort persist — caller cannot act on store errors here.
	_ = c.store.Save(c.cfg.ToolName, token)
}

// cacheEntitlements updates the in-memory entitlement cache.
func (c *Client) cacheEntitlements(ent *Entitlements) {
	if ent == nil {
		return
	}
	c.entMu.Lock()
	c.entitlements = ent
	c.entFetchedAt = time.Now()
	c.entMu.Unlock()
}

// doJSON executes an HTTP request and decodes the JSON response into dst.
// It returns a structured error on non-2xx responses.
func (c *Client) doJSON(req *http.Request, dst any) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return readAPIError(resp)
	}

	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// setUserAgent sets the User-Agent header identifying the tool.
func (c *Client) setUserAgent(req *http.Request) {
	req.Header.Set("User-Agent", fmt.Sprintf("kombify-tool/%s/%s", c.cfg.ToolName, c.cfg.ToolVersion))
}

// readAPIError reads an error response body and returns a structured APIError.
func readAPIError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return &APIError{
		StatusCode: resp.StatusCode,
		Body:       string(body),
	}
}

// Sentinel errors for expected conditions.
var (
	// ErrNotAuthenticated is returned when an operation requires authentication
	// but no token is available.
	ErrNotAuthenticated = fmt.Errorf("toolauth: not authenticated")
	// ErrAuthorizationPending is returned by PollDeviceCode when the user has
	// not yet completed authorization.
	ErrAuthorizationPending = fmt.Errorf("toolauth: authorization pending")
	// ErrDeviceCodeExpired is returned by PollDeviceCode when the device code
	// has expired before the user authorized.
	ErrDeviceCodeExpired = fmt.Errorf("toolauth: device code expired")
)

// APIError represents a non-success HTTP response from the platform API.
type APIError struct {
	StatusCode int
	Body       string
}

// Error implements the error interface.
func (e *APIError) Error() string {
	return fmt.Sprintf("toolauth: API error %d: %s", e.StatusCode, e.Body)
}
