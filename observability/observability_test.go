package observability

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	sentry "github.com/getsentry/sentry-go"
)

func TestMustInit_NoOpWhenDSNMissing(t *testing.T) {
	t.Setenv("SENTRY_DSN", "")
	shutdown := MustInit(Config{Service: "test"})
	t.Cleanup(shutdown)

	if IsEnabled() {
		t.Fatal("expected Sentry to be disabled without DSN")
	}
}

func TestCaptureErr_NilReturnsNil(t *testing.T) {
	if err := CaptureErr(context.Background(), nil); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestCaptureErr_ReturnsOriginal(t *testing.T) {
	want := errors.New("boom")
	got := CaptureErr(context.Background(), want)
	if !errors.Is(got, want) {
		t.Fatalf("expected original error, got %v", got)
	}
}

func TestScrubPII_RemovesAuthHeadersAndQuery(t *testing.T) {
	event := &sentry.Event{
		Request: &sentry.Request{
			URL:     "https://api.kombify.io/v1/users?token=SECRET",
			Data:    "should-be-dropped",
			Cookies: "session=abc",
			Headers: map[string]string{
				"Authorization": "Bearer secret",
				"X-User-Email":  "test@kombify.io",
				"Content-Type":  "application/json",
			},
		},
	}

	got := scrubPII(event, nil)

	if got.Request.Data != "" {
		t.Error("body not scrubbed")
	}
	if got.Request.Cookies != "" {
		t.Error("cookies not scrubbed")
	}
	if got.Request.Headers["Authorization"] != "[scrubbed]" {
		t.Error("Authorization header not scrubbed")
	}
	if got.Request.Headers["X-User-Email"] != "[scrubbed]" {
		t.Error("X-User-Email not scrubbed")
	}
	if got.Request.Headers["Content-Type"] != "application/json" {
		t.Error("Content-Type should not have been scrubbed")
	}
	if got.Request.URL != "https://api.kombify.io/v1/users" {
		t.Errorf("query not stripped: %s", got.Request.URL)
	}
}

func TestDefaultTracesRate(t *testing.T) {
	if defaultTracesRate("prod") != 0.1 {
		t.Error("prod traces rate should be 0.1")
	}
	if defaultTracesRate("dev") != 1.0 {
		t.Error("dev traces rate should be 1.0")
	}
}

func TestMiddleware_PassthroughWhenDisabled(t *testing.T) {
	t.Setenv("SENTRY_DSN", "")
	shutdown := MustInit(Config{Service: "test"})
	t.Cleanup(shutdown)

	called := false
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Fatal("middleware did not pass through to handler")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}
