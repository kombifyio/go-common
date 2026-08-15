// Package authflow implements the browser-facing OIDC auth-code flow for
// kombify backend services. It is intentionally small and side-effect free:
// provider metadata comes from an [oidcclient.Registry], code exchange is
// abstracted behind [oidcclient.CodeExchanger] for testing, and successful
// callbacks mint a [authsession] cookie consumed by the session middleware.
//
// Donor: kombify-Techstack/pkg/v2/auth/flow (lifted 2026-05-03 and rebound
// to the shared oidcclient + authsession packages).
package authflow

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/kombifyio/go-common/authsession"
	"github.com/kombifyio/go-common/oidcclient"
)

const defaultStateLifetime = 5 * time.Minute

// Errors returned by the flow service.
var (
	ErrInvalidConfig = errors.New("authflow: invalid configuration")
	ErrInvalidState  = errors.New("authflow: invalid state")
	ErrMissingTenant = errors.New("authflow: tenant_id is required")
)

// TenantResolver maps verified OIDC claims to the tenant id stamped into the
// session cookie. Returning an empty string or non-nil error redirects the
// browser to the login error page with reason `tenant_resolve_failed`.
//
// Defaults to a function that returns the explicit tenant_id query
// parameter (or DefaultTenantID) when nil — see [Service.handleLogin].
type TenantResolver func(ctx context.Context, claims *oidcclient.Claims, providerID, requestedTenant string) (string, error)

// UserUpsert is an optional hook called after successful claim verification
// and before the session cookie is minted. It lets the consumer create or
// update its user record (e.g. into PocketBase / Postgres). Returning an
// error redirects to the login error page with reason `user_upsert_failed`.
type UserUpsert func(ctx context.Context, claims *oidcclient.Claims, tenantID, providerID string) error

// CallbackPath is the path appended to the request scheme+host to derive the
// `redirect_uri` sent to identity providers. It MUST match the path
// registered with the IdP. Override via [Config.CallbackPath].
const CallbackPath = "/api/v1/auth/callback"

// Config configures a [Service].
type Config struct {
	// Providers is the registry of configured OIDC providers. Required.
	Providers *oidcclient.Registry
	// Sessions mints HS256 session JWTs after a successful callback. Required.
	Sessions *authsession.Manager
	// StateSecret signs the short-lived state token (CSRF + redirect carrier).
	// Must be at least 32 bytes.
	StateSecret []byte

	// DefaultProviderID is used when /login is called without an explicit
	// `provider` query parameter and the registry has more than one entry.
	DefaultProviderID string
	// DefaultTenantID is stamped into session claims when neither the
	// `tenant_id` query parameter nor the [TenantResolver] supplies one.
	DefaultTenantID string
	// DefaultReturnTo is the post-login redirect path. Defaults to "/".
	DefaultReturnTo string
	// LoginErrorPath is where the callback redirects on failure. Defaults to
	// "/login".
	LoginErrorPath string
	// CallbackPath overrides the default OIDC callback path. Defaults to
	// [CallbackPath].
	CallbackPath string

	// SessionCookieName is the cookie minted on successful login. Defaults
	// to [authsession.DefaultSessionCookieName].
	SessionCookieName string
	// SessionCookieSecure controls the cookie's Secure flag. Set true in
	// production.
	SessionCookieSecure bool

	// Exchanger overrides the default RFC-6749 code exchanger. Tests inject
	// a fake; production uses [oidcclient.NewHTTPCodeExchanger].
	Exchanger oidcclient.CodeExchanger

	// TenantResolver maps verified OIDC claims to the session tenant id.
	// Optional; when nil the request `tenant_id` (or DefaultTenantID) is used.
	TenantResolver TenantResolver
	// UserUpsert is an optional post-verification hook for user provisioning.
	UserUpsert UserUpsert

	// Now is injectable for tests.
	Now func() time.Time
}

// Service serves the OIDC auth-code endpoints.
type Service struct {
	cfg       Config
	exchanger oidcclient.CodeExchanger
	now       func() time.Time
}

// NewService validates Config and returns a new auth-code flow service.
func NewService(cfg Config) (*Service, error) {
	if cfg.Providers == nil || cfg.Providers.Len() == 0 {
		return nil, fmt.Errorf("%w: at least one provider is required", ErrInvalidConfig)
	}
	if cfg.Sessions == nil {
		return nil, fmt.Errorf("%w: sessions manager is required", ErrInvalidConfig)
	}
	if len(cfg.StateSecret) < 32 {
		return nil, fmt.Errorf("%w: state secret must be at least 32 bytes", ErrInvalidConfig)
	}
	if cfg.DefaultReturnTo == "" {
		cfg.DefaultReturnTo = "/"
	}
	if cfg.LoginErrorPath == "" {
		cfg.LoginErrorPath = "/login"
	}
	if cfg.CallbackPath == "" {
		cfg.CallbackPath = CallbackPath
	}
	if cfg.SessionCookieName == "" {
		cfg.SessionCookieName = authsession.DefaultSessionCookieName
	}
	exchanger := cfg.Exchanger
	if exchanger == nil {
		exchanger = oidcclient.NewHTTPCodeExchanger()
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Service{
		cfg: Config{
			Providers:           cfg.Providers,
			Sessions:            cfg.Sessions,
			StateSecret:         cfg.StateSecret,
			DefaultProviderID:   cfg.DefaultProviderID,
			DefaultTenantID:     cfg.DefaultTenantID,
			DefaultReturnTo:     sanitizeReturnTo(cfg.DefaultReturnTo, "/"),
			LoginErrorPath:      sanitizeReturnTo(cfg.LoginErrorPath, "/login"),
			CallbackPath:        cfg.CallbackPath,
			SessionCookieName:   cfg.SessionCookieName,
			SessionCookieSecure: cfg.SessionCookieSecure,
			TenantResolver:      cfg.TenantResolver,
			UserUpsert:          cfg.UserUpsert,
		},
		exchanger: exchanger,
		now:       now,
	}, nil
}

// ProvidersHandler exposes the configured providers for frontend bootstrap.
func (s *Service) ProvidersHandler() http.Handler {
	return http.HandlerFunc(s.handleProviders)
}

// LoginHandler starts the auth-code redirect flow.
func (s *Service) LoginHandler() http.Handler {
	return http.HandlerFunc(s.handleLogin)
}

// CallbackHandler completes the auth-code flow, mints a session cookie, and
// redirects the browser to the requested return path.
func (s *Service) CallbackHandler() http.Handler {
	return http.HandlerFunc(s.handleCallback)
}

// LogoutHandler clears the session cookie and redirects to the login page
// (or a caller-provided next path).
func (s *Service) LogoutHandler() http.Handler {
	return http.HandlerFunc(s.handleLogout)
}

func (s *Service) handleProviders(w http.ResponseWriter, r *http.Request) {
	ids := s.cfg.Providers.IDs()
	sort.Strings(ids)
	type providerInfo struct {
		ID     string `json:"id"`
		Kind   string `json:"kind"`
		Issuer string `json:"issuer"`
	}
	resp := struct {
		Providers []providerInfo `json:"providers"`
	}{Providers: make([]providerInfo, 0, len(ids))}
	for _, id := range ids {
		p, err := s.cfg.Providers.Get(id)
		if err != nil {
			continue
		}
		resp.Providers = append(resp.Providers, providerInfo{
			ID:     p.ID(),
			Kind:   string(p.Kind()),
			Issuer: p.Issuer(),
		})
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) {
	provider, err := s.resolveProvider(strings.TrimSpace(r.URL.Query().Get("provider")))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		tenantID = s.cfg.DefaultTenantID
	}
	// TenantResolver runs again on callback after claims are verified; here
	// we only need a non-empty placeholder so /login can fail fast for
	// pure self-hosted configurations that lack a tenant.
	if tenantID == "" && s.cfg.TenantResolver == nil {
		http.Error(w, ErrMissingTenant.Error(), http.StatusBadRequest)
		return
	}
	returnTo := sanitizeReturnTo(r.URL.Query().Get("return_to"), s.cfg.DefaultReturnTo)
	verifier, challenge, err := oidcclient.PKCEVerifier()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	state, err := s.issueState(loginState{
		ProviderID:   provider.ID(),
		TenantID:     tenantID,
		ReturnTo:     returnTo,
		PKCEVerifier: verifier,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redirectURI := buildAbsoluteURL(r, s.cfg.CallbackPath)
	// #nosec G710 -- NewProvider restricts the server-configured authorization
	// endpoint to an absolute HTTP(S) URL; request values are query-encoded.
	http.Redirect(w, r, provider.AuthCodeURL(redirectURI, state, challenge), http.StatusFound)
}

func (s *Service) handleCallback(w http.ResponseWriter, r *http.Request) {
	if errorCode := strings.TrimSpace(r.URL.Query().Get("error")); errorCode != "" {
		s.redirectToLoginError(w, r, errorCode)
		return
	}
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	stateToken := strings.TrimSpace(r.URL.Query().Get("state"))
	if code == "" || stateToken == "" {
		s.redirectToLoginError(w, r, "missing_authorization_code")
		return
	}
	state, err := s.parseState(stateToken)
	if err != nil {
		s.redirectToLoginError(w, r, "invalid_state")
		return
	}
	provider, err := s.resolveProvider(state.ProviderID)
	if err != nil {
		s.redirectToLoginError(w, r, "unknown_provider")
		return
	}
	redirectURI := buildAbsoluteURL(r, s.cfg.CallbackPath)
	exchange, err := s.exchanger.ExchangeCode(r.Context(), provider, oidcclient.CodeExchangeRequest{
		Code:         code,
		RedirectURI:  redirectURI,
		PKCEVerifier: state.PKCEVerifier,
	})
	if err != nil || exchange == nil || strings.TrimSpace(exchange.IDToken) == "" {
		s.redirectToLoginError(w, r, "token_exchange_failed")
		return
	}
	claims, err := provider.Verify(r.Context(), exchange.IDToken)
	if err != nil {
		s.redirectToLoginError(w, r, "invalid_id_token")
		return
	}
	tenantID := state.TenantID
	if s.cfg.TenantResolver != nil {
		resolved, err := s.cfg.TenantResolver(r.Context(), claims, provider.ID(), state.TenantID)
		if err != nil || strings.TrimSpace(resolved) == "" {
			s.redirectToLoginError(w, r, "tenant_resolve_failed")
			return
		}
		tenantID = strings.TrimSpace(resolved)
	}
	if tenantID == "" {
		s.redirectToLoginError(w, r, "tenant_resolve_failed")
		return
	}
	if s.cfg.UserUpsert != nil {
		if err := s.cfg.UserUpsert(r.Context(), claims, tenantID, provider.ID()); err != nil {
			s.redirectToLoginError(w, r, "user_upsert_failed")
			return
		}
	}
	token, err := s.cfg.Sessions.Issue(authsession.Claims{
		Subject:  claims.Subject,
		TenantID: tenantID,
		OrgID:    firstClaim(claims.Raw, "org_id", "org", "project_id"),
		Email:    claims.Email,
		Provider: provider.ID(),
		Role:     firstClaim(claims.Raw, "role", "local_role"),
	})
	if err != nil {
		s.redirectToLoginError(w, r, "session_issue_failed")
		return
	}
	authsession.SetSessionCookie(w, s.cfg.SessionCookieName, token, s.cfg.SessionCookieSecure)
	http.Redirect(w, r, state.ReturnTo, http.StatusFound)
}

func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) {
	next := sanitizeReturnTo(r.URL.Query().Get("next"), s.cfg.LoginErrorPath)
	authsession.ClearSessionCookie(w, s.cfg.SessionCookieName, s.cfg.SessionCookieSecure)
	// #nosec G710 -- sanitizeReturnTo accepts only local absolute-path references
	// and rejects backslashes, control characters, hosts, and schemes.
	http.Redirect(w, r, next, http.StatusFound)
}

func (s *Service) resolveProvider(id string) (*oidcclient.Provider, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		if s.cfg.DefaultProviderID != "" {
			id = s.cfg.DefaultProviderID
		} else if s.cfg.Providers.Len() == 1 {
			ids := s.cfg.Providers.IDs()
			if len(ids) == 1 {
				id = ids[0]
			}
		}
	}
	if id == "" {
		return nil, fmt.Errorf("%w: provider is required", ErrInvalidConfig)
	}
	return s.cfg.Providers.Get(id)
}

type loginState struct {
	ProviderID   string `json:"provider_id"`
	TenantID     string `json:"tenant_id"`
	ReturnTo     string `json:"return_to"`
	PKCEVerifier string `json:"pkv,omitempty"`
	IssuedAt     int64  `json:"iat"`
	ExpiresAt    int64  `json:"exp"`
}

func (s *Service) issueState(state loginState) (string, error) {
	now := s.now().UTC()
	claims := loginState{
		ProviderID:   state.ProviderID,
		TenantID:     state.TenantID,
		ReturnTo:     sanitizeReturnTo(state.ReturnTo, s.cfg.DefaultReturnTo),
		PKCEVerifier: state.PKCEVerifier,
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(defaultStateLifetime).Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal state: %w", err)
	}
	return s.sealState(payload)
}

func (s *Service) parseState(raw string) (*loginState, error) {
	payload, err := s.openState(raw)
	if err != nil {
		return nil, ErrInvalidState
	}
	claims := &loginState{}
	if err := json.Unmarshal(payload, claims); err != nil {
		return nil, ErrInvalidState
	}
	if claims.ProviderID == "" {
		return nil, ErrInvalidState
	}
	now := s.now().UTC().Unix()
	if claims.IssuedAt <= 0 || claims.ExpiresAt <= now {
		return nil, ErrInvalidState
	}
	claims.ReturnTo = sanitizeReturnTo(claims.ReturnTo, s.cfg.DefaultReturnTo)
	return claims, nil
}

func (s *Service) sealState(plaintext []byte) (string, error) {
	aead, err := s.newStateCipher()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("read state nonce: %w", err)
	}
	sealed := aead.Seal(nil, nonce, plaintext, nil)
	buf := append(nonce, sealed...)
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (s *Service) openState(raw string) ([]byte, error) {
	aead, err := s.newStateCipher()
	if err != nil {
		return nil, err
	}
	buf, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, ErrInvalidState
	}
	nonceSize := aead.NonceSize()
	if len(buf) <= nonceSize {
		return nil, ErrInvalidState
	}
	plaintext, err := aead.Open(nil, buf[:nonceSize], buf[nonceSize:], nil)
	if err != nil {
		return nil, ErrInvalidState
	}
	return plaintext, nil
}

func (s *Service) newStateCipher() (cipher.AEAD, error) {
	key := sha256.Sum256(s.cfg.StateSecret)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("build state cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("build state aead: %w", err)
	}
	return aead, nil
}

func (s *Service) redirectToLoginError(w http.ResponseWriter, r *http.Request, code string) {
	target := s.cfg.LoginErrorPath
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	http.Redirect(w, r, target+sep+"error="+url.QueryEscape(code), http.StatusFound)
}

func sanitizeReturnTo(raw, fallback string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	if strings.ContainsAny(raw, "\\\r\n") {
		return fallback
	}
	target, err := url.Parse(raw)
	if err != nil || target.IsAbs() || target.Host != "" ||
		!strings.HasPrefix(target.Path, "/") || strings.HasPrefix(target.Path, "//") {
		return fallback
	}
	return raw
}

func buildAbsoluteURL(r *http.Request, path string) string {
	scheme := "https"
	if r.TLS == nil {
		if proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); proto != "" {
			scheme = proto
		} else {
			scheme = "http"
		}
	}
	host := r.Host
	if forwardedHost := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); forwardedHost != "" {
		host = forwardedHost
	}
	if path == "" {
		path = "/"
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, path)
}

func firstClaim(raw map[string]interface{}, keys ...string) string {
	if raw == nil {
		return ""
	}
	for _, key := range keys {
		if value, ok := raw[key]; ok {
			if s, ok := value.(string); ok {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}
