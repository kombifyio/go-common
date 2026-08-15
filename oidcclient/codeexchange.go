package oidcclient

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
)

// Errors returned by code exchange.
var (
	ErrTokenExchange = errors.New("oidcclient: token exchange failed")
)

// CodeExchanger exchanges an OAuth2 authorization code for an ID token.
//
// Implementations must be safe for concurrent use. The default
// [HTTPCodeExchanger] talks RFC-6749 directly to [Provider.TokenURL].
type CodeExchanger interface {
	ExchangeCode(ctx context.Context, p *Provider, req CodeExchangeRequest) (*CodeExchangeResult, error)
}

// CodeExchangeRequest carries the parameters needed for an authorization-code
// exchange. PKCEVerifier is optional but strongly recommended for public
// clients (no ClientSecret).
type CodeExchangeRequest struct {
	Code         string
	RedirectURI  string
	PKCEVerifier string
}

// CodeExchangeResult is the parsed token endpoint response. Refresh- and
// access-token are exposed for callers that need them; the typical kombify
// flow only consumes IDToken.
type CodeExchangeResult struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// HTTPCodeExchanger is the default RFC-6749 code-exchanger.
type HTTPCodeExchanger struct {
	Client *http.Client
}

// NewHTTPCodeExchanger returns an exchanger with a sane default timeout.
func NewHTTPCodeExchanger() *HTTPCodeExchanger {
	return &HTTPCodeExchanger{Client: &http.Client{Timeout: 30 * time.Second}}
}

// ExchangeCode posts an `application/x-www-form-urlencoded` token request to
// the provider's token endpoint. ClientSecret (if present) is sent as HTTP
// Basic auth. PKCE verifier is sent as a form field.
func (h *HTTPCodeExchanger) ExchangeCode(ctx context.Context, p *Provider, req CodeExchangeRequest) (*CodeExchangeResult, error) {
	if p == nil {
		return nil, fmt.Errorf("%w: provider is nil", ErrInvalidProvider)
	}
	if strings.TrimSpace(req.Code) == "" {
		return nil, fmt.Errorf("%w: code is required", ErrTokenExchange)
	}
	if strings.TrimSpace(req.RedirectURI) == "" {
		return nil, fmt.Errorf("%w: redirect_uri is required", ErrTokenExchange)
	}

	values := url.Values{}
	values.Set("grant_type", "authorization_code")
	values.Set("code", req.Code)
	values.Set("redirect_uri", req.RedirectURI)
	if p.ClientSecret() == "" {
		// public client → client_id in body, no Basic auth
		values.Set("client_id", p.ClientID())
	}
	if req.PKCEVerifier != "" {
		values.Set("code_verifier", req.PKCEVerifier)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL(), strings.NewReader(values.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenExchange, err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")
	if p.ClientSecret() != "" {
		httpReq.SetBasicAuth(p.ClientID(), p.ClientSecret())
	}

	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenExchange, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: status %d body=%s", ErrTokenExchange, resp.StatusCode, truncateForError(body, 256))
	}
	out := &CodeExchangeResult{}
	if err := json.Unmarshal(body, out); err != nil {
		return nil, fmt.Errorf("%w: decode response: %v", ErrTokenExchange, err)
	}
	if strings.TrimSpace(out.IDToken) == "" {
		return nil, fmt.Errorf("%w: response missing id_token", ErrTokenExchange)
	}
	return out, nil
}

func truncateForError(body []byte, max int) string {
	if len(body) <= max {
		return string(body)
	}
	return string(body[:max]) + "..."
}
