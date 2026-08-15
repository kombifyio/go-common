package httputil

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

const requestIDHeader = "X-Request-ID"

type requestIDContextKey struct{}

// RequestID returns a middleware that ensures every request has a request ID.
//
// If the client provides X-Request-ID, it is used (truncated to 128 chars).
// Otherwise a new UUID is generated. The ID is attached to the request context
// and echoed in the response header.
func RequestID() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rid := strings.TrimSpace(r.Header.Get(requestIDHeader))
			if rid == "" {
				rid = uuid.NewString()
			} else if len(rid) > 128 {
				rid = rid[:128]
			}

			ctx := context.WithValue(r.Context(), requestIDContextKey{}, rid)
			w.Header().Set(requestIDHeader, rid)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetRequestID returns the request ID from context, if present.
func GetRequestID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v := ctx.Value(requestIDContextKey{}); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
