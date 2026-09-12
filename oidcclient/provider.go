package oidcclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
)

// Kind enumerates the supported provider flavors. The kind drives default
// discovery URL composition; once a provider is constructed all kinds share
// the same OIDC verification path.
type Kind string

const (
	// KindPocketID is the kombify self-hosted default identity provider
	// (passkey-first OIDC).
	KindPocketID Kind = "pocketid"
	// KindAuth0 is the kombify SaaS identity provider via Cloudflare Edge
	// Router.
	KindAuth0 Kind = "auth0"
	// KindPocketBase is the optional self-hosted alternative — a dedicated
	// PocketBase instance behind the kombify OIDC bridge.
	KindPocketBase Kind = "pocketbase"
	// KindGeneric is any other RFC-compliant OIDC issuer.
	KindGeneric Kind = "generic"
)

// Errors returned by Registry / Provider / PKCE helpers.
var (
	ErrUnknownProvider = errors.New("oidcclient: unknown provider")
	ErrInvalidProvider = errors.New("oidcclient: invalid provider configuration")
)

// ProviderConfig describes a single identity provider entry.
type ProviderConfig struct {
	ID               string   // logical id (per org/tenant), e.g. "primary", "auth0-saas"
	Kind             Kind     // provider flavor (drives default URL composition)
	Issuer           string   // required
	Audience         string   // optional; defaults to ClientID
	ClientID         string   // required for auth code login
	ClientSecret     string   // optional for public clients (use PKCE instead)
	AuthorizationURL string   // optional; derived from issuer when empty
	TokenURL         string   // optional; derived from issuer when empty
	JWKSURL          string   // optional; derived from issuer when empty
	Scopes           []string // optional; defaults to openid/profile/email
}

// Provider is a verified-OIDC bridge for a single identity provider config.
type Provider struct {
	cfg      ProviderConfig
	verifier *Verifier
}

// ID returns the logical provider id.
func (p *Provider) ID() string { return p.cfg.ID }

// Kind returns the provider flavor.
func (p *Provider) Kind() Kind { return p.cfg.Kind }

// Issuer returns the provider issuer URL.
func (p *Provider) Issuer() string { return p.cfg.Issuer }

// ClientID returns the OAuth2 client id used for auth-code login.
func (p *Provider) ClientID() string { return p.cfg.ClientID }

// ClientSecret returns the OAuth2 client secret, if configured.
func (p *Provider) ClientSecret() string { return p.cfg.ClientSecret }

// AuthorizationURL returns the provider authorization endpoint.
func (p *Provider) AuthorizationURL() string { return p.cfg.AuthorizationURL }

// TokenURL returns the provider token endpoint.
func (p *Provider) TokenURL() string { return p.cfg.TokenURL }

// Scopes returns the default scopes used in auth-code requests.
func (p *Provider) Scopes() []string {
	out := make([]string, len(p.cfg.Scopes))
	copy(out, p.cfg.Scopes)
	return out
}

// AuthCodeURL constructs the user-agent redirect URL for starting an
// auth-code flow. When codeChallenge is non-empty PKCE (S256) is added.
func (p *Provider) AuthCodeURL(redirectURI, state, codeChallenge string) string {
	target, _ := url.Parse(p.cfg.AuthorizationURL)
	params := target.Query()
	params.Set("client_id", p.cfg.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(p.cfg.Scopes, " "))
	if state != "" {
		params.Set("state", state)
	}
	if codeChallenge != "" {
		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", "S256")
	}
	target.RawQuery = params.Encode()
	return target.String()
}

// Verify delegates to the underlying OIDC verifier.
func (p *Provider) Verify(ctx context.Context, rawToken string) (*Claims, error) {
	return p.verifier.Verify(ctx, rawToken)
}

// Verifier returns the underlying ID-token verifier (rarely needed by
// callers, exposed for tests and advanced flows).
func (p *Provider) Verifier() *Verifier { return p.verifier }

// NewProvider builds a Provider from a [ProviderConfig]. JWKSURL defaults to
// `<issuer>/.well-known/jwks.json` when not explicitly set; that is the
// convention for both Pocket ID and Auth0. Use [Discover] to populate the
// URL fields from `.well-known/openid-configuration`.
func NewProvider(cfg ProviderConfig) (*Provider, error) {
	if strings.TrimSpace(cfg.ID) == "" {
		return nil, fmt.Errorf("%w: id is required", ErrInvalidProvider)
	}
	switch cfg.Kind {
	case KindPocketID, KindAuth0, KindPocketBase, KindGeneric:
	default:
		return nil, fmt.Errorf("%w: unsupported kind %q", ErrInvalidProvider, cfg.Kind)
	}
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		return nil, fmt.Errorf("%w: issuer is required", ErrInvalidProvider)
	}
	if err := validateHTTPSEndpoint("issuer", issuer); err != nil {
		return nil, err
	}
	endpointBase := strings.TrimRight(issuer, "/")
	clientID := strings.TrimSpace(cfg.ClientID)
	if clientID == "" {
		return nil, fmt.Errorf("%w: client_id is required", ErrInvalidProvider)
	}
	audience := strings.TrimSpace(cfg.Audience)
	if audience == "" {
		audience = clientID
	}
	authorizationURL := strings.TrimSpace(cfg.AuthorizationURL)
	if authorizationURL == "" {
		authorizationURL = endpointBase + "/authorize"
	}
	if err := validateHTTPSEndpoint("authorization_url", authorizationURL); err != nil {
		return nil, err
	}
	tokenURL := strings.TrimSpace(cfg.TokenURL)
	if tokenURL == "" {
		tokenURL = endpointBase + "/oauth/token"
	}
	if err := validateHTTPSEndpoint("token_url", tokenURL); err != nil {
		return nil, err
	}
	jwks := strings.TrimSpace(cfg.JWKSURL)
	if jwks == "" {
		jwks = endpointBase + "/.well-known/jwks.json"
	}
	if err := validateHTTPSEndpoint("jwks_url", jwks); err != nil {
		return nil, err
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	v, err := NewVerifier(VerifierConfig{
		Issuer:   issuer,
		Audience: audience,
		JWKSURL:  jwks,
	})
	if err != nil {
		return nil, err
	}
	return &Provider{cfg: ProviderConfig{
		ID:               cfg.ID,
		Kind:             cfg.Kind,
		Issuer:           issuer,
		Audience:         audience,
		ClientID:         clientID,
		ClientSecret:     cfg.ClientSecret,
		AuthorizationURL: authorizationURL,
		TokenURL:         tokenURL,
		JWKSURL:          jwks,
		Scopes:           scopes,
	}, verifier: v}, nil
}

// validateHTTPSEndpoint keeps provider-controlled network and redirect targets
// on absolute HTTP(S) URLs. HTTP remains supported for loopback/self-hosted
// development, while non-web schemes, relative URLs, and userinfo are rejected.
func validateHTTPSEndpoint(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("%w: %s must be an absolute HTTP(S) URL without userinfo", ErrInvalidProvider, field)
	}
	return nil
}

// Registry holds providers indexed by ID. Safe for concurrent reads after
// construction; write methods take an internal mutex.
type Registry struct {
	mu    sync.RWMutex
	items map[string]*Provider
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{items: map[string]*Provider{}} }

// Add registers (or replaces) a provider.
func (r *Registry) Add(p *Provider) {
	if p == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items[p.ID()] = p
}

// Get returns the provider with the given id.
func (r *Registry) Get(id string) (*Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.items[id]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProvider, id)
	}
	return p, nil
}

// Len returns the number of registered providers.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.items)
}

// IDs returns the registered provider ids in arbitrary order.
func (r *Registry) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.items))
	for k := range r.items {
		out = append(out, k)
	}
	return out
}

// PKCEVerifier returns a fresh RFC-7636 PKCE verifier (43–128 chars,
// base64url unpadded random bytes) plus its S256 challenge. Callers persist
// the verifier server-side keyed by login-state and pass the challenge to
// [Provider.AuthCodeURL].
func PKCEVerifier() (verifier, challenge string, err error) {
	buf := make([]byte, 64)
	if _, err = rand.Read(buf); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}
