package authsession

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

// DefaultSessionCookieName is the recommended cookie name for backends that
// don't have a tool-specific override. Consumers SHOULD pick their own name
// (e.g. "techstack_v2_session", "kombisim_session") to avoid cross-tool
// collisions on shared parent domains.
const DefaultSessionCookieName = "kombify_session"

// Errors returned by Middleware / context helpers.
var (
	ErrMissingClaims = errors.New("authsession: no claims in context")
)

type ctxKey struct{}

// Option configures a [Middleware].
type Option func(*Middleware)

// WithCookieName overrides the default browser session cookie name.
func WithCookieName(name string) Option {
	return func(m *Middleware) {
		if strings.TrimSpace(name) != "" {
			m.cookieName = strings.TrimSpace(name)
		}
	}
}

// Middleware is the bearer-token authentication middleware.
type Middleware struct {
	mgr        *Manager
	cookieName string
}

// NewMiddleware returns a [Middleware] backed by the given session manager.
func NewMiddleware(mgr *Manager, opts ...Option) *Middleware {
	m := &Middleware{mgr: mgr, cookieName: DefaultSessionCookieName}
	for _, opt := range opts {
		if opt != nil {
			opt(m)
		}
	}
	return m
}

// CookieName returns the cookie name this middleware reads.
func (m *Middleware) CookieName() string { return m.cookieName }

// Wrap returns an [http.Handler] that authenticates requests before
// delegating to next. Unauthenticated requests are rejected with 401.
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := tokenFromRequest(r, m.cookieName)
		if !ok {
			writeUnauthorized(w, "missing session token")
			return
		}
		claims, err := m.mgr.Verify(token)
		if err != nil {
			writeUnauthorized(w, "invalid token")
			return
		}
		ctx := WithClaims(r.Context(), claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// WithClaims returns a context carrying the given session claims.
func WithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

// ClaimsFrom returns claims previously stashed by the middleware.
func ClaimsFrom(ctx context.Context) (*Claims, error) {
	v, _ := ctx.Value(ctxKey{}).(*Claims)
	if v == nil {
		return nil, ErrMissingClaims
	}
	return v, nil
}

// TenantFrom is a convenience wrapper returning just the tenant id.
func TenantFrom(ctx context.Context) (string, error) {
	c, err := ClaimsFrom(ctx)
	if err != nil {
		return "", err
	}
	return c.TenantID, nil
}

// SetSessionCookie writes a session cookie with the conventional kombify
// attributes (HttpOnly, SameSite=Lax, Path=/). The secure argument must be
// false only for explicit loopback/local-HTTP development.
func SetSessionCookie(w http.ResponseWriter, name, token string, secure bool) {
	// #nosec G124 -- Secure is an explicit environment policy so local HTTP can
	// work; HttpOnly and SameSite=Lax remain mandatory for every caller.
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie writes an expired session cookie to log the user out.
func ClearSessionCookie(w http.ResponseWriter, name string, secure bool) {
	// #nosec G124 -- Secure mirrors the cookie being cleared and is false only
	// for explicit local HTTP; HttpOnly and SameSite=Lax remain mandatory.
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func tokenFromRequest(r *http.Request, cookieName string) (string, bool) {
	if tok, ok := bearerFromHeader(r); ok {
		return tok, true
	}
	if cookieName == "" {
		cookieName = DefaultSessionCookieName
	}
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return "", false
	}
	tok := strings.TrimSpace(cookie.Value)
	if tok == "" {
		return "", false
	}
	return tok, true
}

func bearerFromHeader(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", false
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	tok := strings.TrimSpace(parts[1])
	if tok == "" {
		return "", false
	}
	return tok, true
}

func writeUnauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="kombify"`)
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"` + msg + `"}`))
}
