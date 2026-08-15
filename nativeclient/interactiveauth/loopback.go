// Package interactiveauth implements the two human-interactive native OAuth
// flows of NATIVE-CLIENT-PLATFORM-STANDARD.md section 4, composed on the
// transport-pure [oidcclient] package:
//
//   - Flow A: loopback redirect with PKCE (RFC 8252) for desktops that can
//     open a system browser.
//   - Flow B: device authorization grant (RFC 8628) for headless/CLI use.
//
// Native clients are public clients: no client secret is used anywhere in
// this package. Universal Login happens in the system browser, never in an
// embedded credential-collecting WebView. The package carries no
// provider-specific branches beyond RFC-standard endpoints.
package interactiveauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/kombifyio/go-common/oidcclient"
)

// Errors returned by the interactive flows.
var (
	ErrBrowserOpen   = errors.New("interactiveauth: opening the system browser failed")
	ErrCallback      = errors.New("interactiveauth: authorization callback failed")
	ErrFlowTimeout   = errors.New("interactiveauth: authorization timed out")
	ErrAccessDenied  = errors.New("interactiveauth: authorization was denied")
	ErrInvalidConfig = errors.New("interactiveauth: invalid configuration")
)

// LoopbackConfig configures the RFC 8252 loopback PKCE flow.
type LoopbackConfig struct {
	// Provider supplies authorization/token endpoints, client id, and scopes.
	Provider *oidcclient.Provider
	// OpenBrowser opens the authorization URL in the system browser. Required:
	// the flow never embeds a login surface.
	OpenBrowser func(authURL string) error
	// Timeout bounds the whole interaction. Defaults to 5 minutes.
	Timeout time.Duration
	// SuccessHTML is served to the browser after a successful callback.
	// A minimal English default is used when empty.
	SuccessHTML string
	// Exchanger defaults to [oidcclient.NewHTTPCodeExchanger].
	Exchanger oidcclient.CodeExchanger
}

const defaultSuccessHTML = `<!doctype html><meta charset="utf-8"><title>Signed in</title>` +
	`<body style="font-family:system-ui;margin:3rem">You are signed in. You can close this window and return to the application.</body>`

// oauthErrorAccessDenied is the RFC 6749/8628 error code for user denial.
const oauthErrorAccessDenied = "access_denied"

type callbackResult struct {
	code string
	err  error
}

// callbackHandler serves the loopback redirect endpoint: it validates state,
// maps provider errors, and delivers exactly one result.
func callbackHandler(state, successHTML string, results chan<- callbackResult) http.HandlerFunc {
	deliver := func(result callbackResult) {
		select {
		case results <- result:
		default:
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		query := r.URL.Query()
		if subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(state)) != 1 {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			deliver(callbackResult{err: fmt.Errorf("%w: state mismatch", ErrCallback)})
			return
		}
		if authErr := query.Get("error"); authErr != "" {
			http.Error(w, "authorization failed", http.StatusBadRequest)
			wrapped := ErrCallback
			if authErr == oauthErrorAccessDenied {
				wrapped = ErrAccessDenied
			}
			deliver(callbackResult{err: fmt.Errorf("%w: %s (%s)", wrapped, authErr, query.Get("error_description"))})
			return
		}
		code := query.Get("code")
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			deliver(callbackResult{err: fmt.Errorf("%w: missing code", ErrCallback)})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(successHTML))
		deliver(callbackResult{code: code})
	}
}

// LoopbackPKCE runs the full RFC 8252 flow: it binds an ephemeral listener on
// 127.0.0.1 (literal address per RFC 8252 section 7.3), opens the system
// browser on the provider's authorization URL with a fresh S256 PKCE
// challenge and state, waits for exactly one matching callback, and exchanges
// the code for tokens.
func LoopbackPKCE(ctx context.Context, cfg LoopbackConfig) (*oidcclient.CodeExchangeResult, error) {
	if cfg.Provider == nil || cfg.OpenBrowser == nil {
		return nil, fmt.Errorf("%w: provider and OpenBrowser are required", ErrInvalidConfig)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCallback, err)
	}
	defer func() { _ = listener.Close() }()
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", listener.Addr().(*net.TCPAddr).Port)

	state, err := randomToken()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCallback, err)
	}
	verifier, challenge, err := oidcclient.PKCEVerifier()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCallback, err)
	}

	results := make(chan callbackResult, 1)
	successHTML := cfg.SuccessHTML
	if successHTML == "" {
		successHTML = defaultSuccessHTML
	}
	server := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler:           callbackHandler(state, successHTML, results),
	}
	go func() { _ = server.Serve(listener) }()
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	if err := cfg.OpenBrowser(cfg.Provider.AuthCodeURL(redirectURI, state, challenge)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBrowserOpen, err)
	}

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %v", ErrFlowTimeout, ctx.Err())
	case result := <-results:
		if result.err != nil {
			return nil, result.err
		}
		exchanger := cfg.Exchanger
		if exchanger == nil {
			exchanger = oidcclient.NewHTTPCodeExchanger()
		}
		return exchanger.ExchangeCode(ctx, cfg.Provider, oidcclient.CodeExchangeRequest{
			Code:         result.code,
			RedirectURI:  redirectURI,
			PKCEVerifier: verifier,
		})
	}
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
