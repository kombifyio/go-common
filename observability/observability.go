// Package observability wires kombify Go services into Sentry for error
// reporting and performance tracing.
//
// This is the SINGLE SOURCE OF TRUTH for how internal kombify Go services
// initialize Sentry — defaults (sample rates, PII scrubbing, release tagging,
// user-context extraction from edgeauth headers) are enforced here so every
// service gets identical, DSGVO-safe behavior.
//
// Scope: SaaS services only (Ebene 2 per PRODUCT-SEGMENTATION.md).
// OSS tools (Ebene 1 — Sim, SpeechKit, StackKits, TechStack-OSS) MUST NOT
// import this package. See ../kombify Core/standards/OBSERVABILITY-STANDARD.md.
//
// Usage:
//
//	func main() {
//	    shutdown := observability.MustInit(observability.Config{
//	        Service:     "kombify-cloud-backend",
//	        Environment: os.Getenv("SENTRY_ENVIRONMENT"),
//	        Release:     os.Getenv("SENTRY_RELEASE"),
//	    })
//	    defer shutdown()
//
//	    mux := http.NewServeMux()
//	    // ... register handlers ...
//	    http.ListenAndServe(":8080", observability.Middleware(mux))
//	}
package observability

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kombifyio/go-common/identity"
	sentry "github.com/getsentry/sentry-go"
	sentryhttp "github.com/getsentry/sentry-go/http"
)

// Config configures Sentry initialization for a kombify SaaS Go service.
type Config struct {
	// Service is the Sentry project slug (e.g. "kombify-cloud-backend").
	// Required when Enabled=true.
	Service string

	// DSN is the Sentry DSN. Defaults to os.Getenv("SENTRY_DSN").
	// When empty, observability is disabled (safe for local dev).
	DSN string

	// Environment is the Sentry environment tag ("prod", "dev", "preview").
	// Defaults to os.Getenv("SENTRY_ENVIRONMENT") or "prod".
	Environment string

	// Release is the release identifier, typically the Git SHA.
	// Defaults to os.Getenv("SENTRY_RELEASE").
	Release string

	// TracesSampleRate overrides the default (0.1 in prod, 1.0 in dev).
	TracesSampleRate *float64

	// Debug enables Sentry SDK debug logging.
	Debug bool
}

// MustInit initializes Sentry with kombify defaults. Safe to call even when
// SENTRY_DSN is unset — it becomes a no-op and returns a no-op shutdown.
//
// Returns a shutdown function that should be deferred in main().
func MustInit(cfg Config) func() {
	dsn := cfg.DSN
	if dsn == "" {
		dsn = os.Getenv("SENTRY_DSN")
	}
	if dsn == "" {
		// No-op mode. Services in local dev / OSS-style deployment.
		return func() {}
	}

	env := cfg.Environment
	if env == "" {
		env = os.Getenv("SENTRY_ENVIRONMENT")
	}
	if env == "" {
		env = "prod"
	}

	release := cfg.Release
	if release == "" {
		release = os.Getenv("SENTRY_RELEASE")
	}

	traces := defaultTracesRate(env)
	if cfg.TracesSampleRate != nil {
		traces = *cfg.TracesSampleRate
	}

	err := sentry.Init(sentry.ClientOptions{
		Dsn:              dsn,
		Environment:      env,
		Release:          release,
		ServerName:       cfg.Service,
		AttachStacktrace: true,
		EnableTracing:    traces > 0,
		TracesSampleRate: traces,
		SendDefaultPII:   false,
		Debug:            cfg.Debug,
		BeforeSend:       scrubPII,
	})
	if err != nil {
		// Do not fatal — observability failure must not take down the service.
		fmt.Fprintf(os.Stderr, "observability: sentry init failed: %v\n", err)
		return func() {}
	}

	sentry.ConfigureScope(func(scope *sentry.Scope) {
		scope.SetTag("service", cfg.Service)
	})

	return func() {
		sentry.Flush(5 * time.Second)
	}
}

// Middleware wraps an http.Handler with:
//   - Panic recovery (reported to Sentry, then re-raised as 500)
//   - Request-scoped Sentry hub
//   - User context from edgeauth identity headers (via identity.FromContext)
//
// Use AFTER edgeauth.Middleware so identity is already in context.
func Middleware(next http.Handler) http.Handler {
	// sentryhttp handles panic recovery + hub-per-request automatically.
	sentryHandler := sentryhttp.New(sentryhttp.Options{
		Repanic:         true,
		WaitForDelivery: false,
	})

	return sentryHandler.Handle(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hub := sentry.GetHubFromContext(r.Context()); hub != nil {
			hub.Scope().SetRequest(r)
			if id := identity.FromContext(r.Context()); id.IsAuthenticated() {
				hub.Scope().SetUser(sentry.User{
					ID:       id.UserID,
					Email:    id.Email,
					Username: id.UserID,
				})
				if id.OrgID != "" {
					hub.Scope().SetTag("org_id", id.OrgID)
				}
				if id.Tier != "" {
					hub.Scope().SetTag("tier", id.Tier)
				}
			}
		}
		next.ServeHTTP(w, r)
	}))
}

// CaptureErr reports err to Sentry attached to the request hub when present,
// otherwise to the global hub. Returns the original error unchanged so it can
// be used in `return observability.CaptureErr(ctx, err)` chains.
func CaptureErr(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	hub := sentry.GetHubFromContext(ctx)
	if hub == nil {
		hub = sentry.CurrentHub()
	}
	hub.CaptureException(err)
	return err
}

// defaultTracesRate follows OBSERVABILITY-STANDARD.md §9.
//
// Profiles are configured per-transaction in sentry-go (not a ClientOptions
// rate) — see sentry.StartTransaction.WithProfileSampleRate. We leave that to
// call-sites that want it.
func defaultTracesRate(env string) float64 {
	if env == "prod" {
		return 0.1
	}
	return 1.0
}

// scrubPII is the BeforeSend hook enforcing the PII rules from
// OBSERVABILITY-STANDARD.md §6. It strips request bodies, auth headers and
// cookies from outgoing events before they leave the process.
func scrubPII(event *sentry.Event, _ *sentry.EventHint) *sentry.Event {
	if event.Request != nil {
		event.Request.Data = "" // body
		event.Request.Cookies = ""
		if event.Request.Headers != nil {
			for k := range event.Request.Headers {
				lk := strings.ToLower(k)
				if lk == "authorization" || lk == "cookie" || lk == "set-cookie" ||
					strings.HasPrefix(lk, "x-user-") || strings.HasPrefix(lk, "x-org-") {
					event.Request.Headers[k] = "[scrubbed]"
				}
			}
		}
		// Drop query string from URL.
		if i := strings.IndexByte(event.Request.URL, '?'); i >= 0 {
			event.Request.URL = event.Request.URL[:i]
		}
	}
	return event
}

// ErrObservabilityDisabled is returned by utilities that require Sentry but
// the SDK is in no-op mode. Rarely needed — most code should check with
// IsEnabled() before branching.
var ErrObservabilityDisabled = errors.New("observability: disabled (no SENTRY_DSN)")

// IsEnabled reports whether Sentry was initialized successfully.
func IsEnabled() bool {
	return sentry.CurrentHub().Client() != nil
}
