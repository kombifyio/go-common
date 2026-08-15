package servicecall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/kombifyio/go-common/identity"
)

// Client is an HTTP client that attaches service-call tokens to outbound
// requests. Safe for concurrent use.
type Client struct {
	cfg  Config
	http *http.Client
}

// NewClient builds a service-call client. cfg.ServiceName, cfg.Target and
// cfg.Secret are required; a zero TokenTTL falls back to DefaultTokenTTL.
func NewClient(cfg Config) (*Client, error) {
	if cfg.ServiceName == "" {
		return nil, errors.New("servicecall: ServiceName required")
	}
	if cfg.Target == "" {
		return nil, errors.New("servicecall: Target required")
	}
	if cfg.Secret == "" {
		return nil, ErrEmptySecret
	}
	if cfg.TokenTTL <= 0 {
		cfg.TokenTTL = DefaultTokenTTL
	}
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// WithHTTPClient swaps the underlying http.Client. Returns c for chaining.
func (c *Client) WithHTTPClient(h *http.Client) *Client {
	if h != nil {
		c.http = h
	}
	return c
}

// Do attaches the service-auth header to req and forwards it to the inner
// http.Client. If obo is non-nil, the end-user context is embedded in the
// token for downstream attribution.
func (c *Client) Do(ctx context.Context, req *http.Request, obo *OnBehalfOf) (*http.Response, error) {
	reqID := req.Header.Get("X-Request-ID")
	token, err := IssueToken(c.cfg, c.cfg.Target, obo, reqID)
	if err != nil {
		return nil, err
	}
	req.Header.Set(HeaderServiceAuth, token)
	return c.http.Do(req.WithContext(ctx))
}

// Get executes GET url with an auth header attached.
func (c *Client) Get(ctx context.Context, url string, obo *OnBehalfOf) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(ctx, req, obo)
}

// PostJSON marshals body as JSON and POSTs it to url with an auth header.
// A nil body sends no payload.
func (c *Client) PostJSON(ctx context.Context, url string, body interface{}, obo *OnBehalfOf) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.Do(ctx, req, obo)
}

// PostStream POSTs body as JSON with `Accept: text/event-stream` and returns
// the http.Response for SSE consumption. The caller is responsible for
// closing resp.Body and parsing the `data: …` frames.
//
// Unlike PostJSON, the underlying http.Client used here has no client-side
// timeout so long-running generations and agent streams are bounded only by
// ctx. Cancel ctx (or let it expire) to terminate the stream cleanly.
//
// Typical caller pattern:
//
//	resp, err := client.PostStream(ctx, targetURL, body, obo)
//	if err != nil { return err }
//	defer resp.Body.Close()
//	scanner := bufio.NewScanner(resp.Body)
//	for scanner.Scan() { line := scanner.Text(); … }
func (c *Client) PostStream(ctx context.Context, url string, body interface{}, obo *OnBehalfOf) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

	reqID := req.Header.Get("X-Request-ID")
	token, err := IssueToken(c.cfg, c.cfg.Target, obo, reqID)
	if err != nil {
		return nil, err
	}
	req.Header.Set(HeaderServiceAuth, token)

	streamHTTP := &http.Client{Timeout: 0}
	return streamHTTP.Do(req.WithContext(ctx))
}

// OnBehalfOfIdentity converts an identity.Identity into an OnBehalfOf.
// Returns nil when id has no UserID — the call is then treated as purely
// service-to-service with no end-user attribution.
func OnBehalfOfIdentity(id *identity.Identity) *OnBehalfOf {
	if id == nil || id.UserID == "" {
		return nil
	}
	return &OnBehalfOf{
		Sub:   id.UserID,
		OrgID: id.OrgID,
		Email: id.Email,
		Roles: id.Roles,
	}
}
