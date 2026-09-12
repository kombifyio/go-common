package httputil

import (
	"net/http"
	"net/url"
	"os"
	"strings"
)

// ApplySecurityHeaders sets a minimal set of security headers.
//
// Set ALLOWED_FRAME_ORIGINS to a comma or space-separated list of origins
// (e.g. "https://kombify.io https://kombify.space" or
// "https://kombify.io,https://kombify.space") to allow embedding in iframes.
// When set, X-Frame-Options is replaced with Content-Security-Policy:
// frame-ancestors to allow embedding in the kombify Cloud portal.
// Each origin is validated as a proper URL origin to prevent CSP injection.
func ApplySecurityHeaders(h http.Header) {
	h.Set("X-Content-Type-Options", "nosniff")
	if origins := os.Getenv("ALLOWED_FRAME_ORIGINS"); origins != "" {
		var safe []string
		// Accept both comma and space as separators (users mix them up).
		for _, o := range splitOrigins(origins) {
			if sanitized := sanitizeOrigin(o); sanitized != "" {
				safe = append(safe, sanitized)
			}
		}
		if len(safe) > 0 {
			h.Set("Content-Security-Policy", "frame-ancestors 'self' "+strings.Join(safe, " "))
		} else {
			h.Set("X-Frame-Options", "DENY")
		}
	} else {
		h.Set("X-Frame-Options", "DENY")
	}
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	h.Set("X-XSS-Protection", "1; mode=block")
}

// splitOrigins splits an origin string by both commas and whitespace,
// handling mixed separators like "https://a.com, https://b.com".
func splitOrigins(s string) []string {
	// Replace commas with spaces, then split on whitespace.
	return strings.Fields(strings.ReplaceAll(s, ",", " "))
}

// sanitizeOrigin validates that a string is a proper URL origin (scheme://host)
// and does not contain characters that could inject additional CSP directives.
func sanitizeOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	if u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// SecurityHeadersMiddleware applies security headers to all responses.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ApplySecurityHeaders(w.Header())
		next.ServeHTTP(w, r)
	})
}
