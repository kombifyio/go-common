package toolauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestReportUsage_BuffersEvents(t *testing.T) {
	c := newTestClient(t, "http://localhost", newMemStore())

	events := []UsageEvent{
		{Metric: "transcription_minutes", Value: 5.2, At: time.Now()},
		{Metric: "api_calls", Value: 1, At: time.Now()},
	}

	if err := c.ReportUsage(context.Background(), events...); err != nil {
		t.Fatalf("ReportUsage() error: %v", err)
	}

	c.usageMu.Lock()
	bufLen := len(c.usageBuf)
	c.usageMu.Unlock()

	if bufLen != 2 {
		t.Errorf("buffer length = %d, want 2", bufLen)
	}
}

func TestReportUsage_EmptyEventsIsNoop(t *testing.T) {
	c := newTestClient(t, "http://localhost", newMemStore())

	if err := c.ReportUsage(context.Background()); err != nil {
		t.Fatalf("ReportUsage() with no events: error: %v", err)
	}

	c.usageMu.Lock()
	bufLen := len(c.usageBuf)
	c.usageMu.Unlock()

	if bufLen != 0 {
		t.Errorf("buffer length = %d, want 0", bufLen)
	}
}

func TestFlushUsage_SendsBufferedEvents(t *testing.T) {
	var receivedPayload usagePayload
	var flushCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/tools/usage":
			flushCount.Add(1)
			if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
				t.Errorf("decode usage payload: %v", err)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer valid-token" {
				t.Errorf("Authorization = %q, want %q", got, "Bearer valid-token")
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	store := newMemStore()
	c := newTestClient(t, srv.URL, store)

	// Set up valid token.
	c.mu.Lock()
	c.token = &TokenPair{
		AccessToken:  "valid-token",
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		UserID:       "usr-1",
	}
	c.mu.Unlock()

	now := time.Now()
	events := []UsageEvent{
		{Metric: "transcription_minutes", Value: 5.2, At: now},
		{Metric: "api_calls", Value: 1, At: now},
	}
	_ = c.ReportUsage(context.Background(), events...)

	if err := c.flushUsage(context.Background()); err != nil {
		t.Fatalf("flushUsage() error: %v", err)
	}

	if flushCount.Load() != 1 {
		t.Errorf("flush endpoint called %d times, want 1", flushCount.Load())
	}
	if receivedPayload.Tool != "speechkit" {
		t.Errorf("payload Tool = %q, want %q", receivedPayload.Tool, "speechkit")
	}
	if len(receivedPayload.Events) != 2 {
		t.Errorf("payload events count = %d, want 2", len(receivedPayload.Events))
	}

	// Buffer should be empty after flush.
	c.usageMu.Lock()
	bufLen := len(c.usageBuf)
	c.usageMu.Unlock()
	if bufLen != 0 {
		t.Errorf("buffer length after flush = %d, want 0", bufLen)
	}
}

func TestFlushUsage_EmptyBufferIsNoop(t *testing.T) {
	c := newTestClient(t, "http://localhost", newMemStore())

	if err := c.flushUsage(context.Background()); err != nil {
		t.Fatalf("flushUsage() on empty buffer error: %v", err)
	}
}

func TestFlushUsage_PutsEventsBackOnHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/tools/usage":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"server error"}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	store := newMemStore()
	c := newTestClient(t, srv.URL, store)

	// Set up valid token.
	c.mu.Lock()
	c.token = &TokenPair{
		AccessToken:  "valid-token",
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		UserID:       "usr-1",
	}
	c.mu.Unlock()

	events := []UsageEvent{
		{Metric: "test_metric", Value: 1, At: time.Now()},
	}
	_ = c.ReportUsage(context.Background(), events...)

	err := c.flushUsage(context.Background())
	if err == nil {
		t.Fatal("expected error from flushUsage on server error")
	}

	// Events should be put back in the buffer for retry.
	c.usageMu.Lock()
	bufLen := len(c.usageBuf)
	c.usageMu.Unlock()
	if bufLen != 1 {
		t.Errorf("buffer length after failed flush = %d, want 1 (events should be put back)", bufLen)
	}
}

func TestFlushUsage_PutsEventsBackOnNoToken(t *testing.T) {
	c := newTestClient(t, "http://localhost", newMemStore())

	events := []UsageEvent{
		{Metric: "test_metric", Value: 1, At: time.Now()},
	}
	_ = c.ReportUsage(context.Background(), events...)

	// No token set, so GetAccessToken should fail.
	err := c.flushUsage(context.Background())
	if err == nil {
		t.Fatal("expected error from flushUsage without auth token")
	}

	// Events should be preserved.
	c.usageMu.Lock()
	bufLen := len(c.usageBuf)
	c.usageMu.Unlock()
	if bufLen != 1 {
		t.Errorf("buffer length = %d, want 1 (events should be put back)", bufLen)
	}
}

func TestFlushUsage_PreservesOrderOnPutBack(t *testing.T) {
	c := newTestClient(t, "http://localhost", newMemStore())

	// Buffer first batch.
	_ = c.ReportUsage(context.Background(), UsageEvent{Metric: "first", Value: 1, At: time.Now()})

	// flushUsage will fail (no token), putting "first" back.
	_ = c.flushUsage(context.Background())

	// Add second event after the failed flush.
	_ = c.ReportUsage(context.Background(), UsageEvent{Metric: "second", Value: 2, At: time.Now()})

	c.usageMu.Lock()
	defer c.usageMu.Unlock()

	if len(c.usageBuf) != 2 {
		t.Fatalf("buffer length = %d, want 2", len(c.usageBuf))
	}
	// The put-back batch ("first") should come before the new event ("second").
	if c.usageBuf[0].Metric != "first" {
		t.Errorf("usageBuf[0].Metric = %q, want %q", c.usageBuf[0].Metric, "first")
	}
	if c.usageBuf[1].Metric != "second" {
		t.Errorf("usageBuf[1].Metric = %q, want %q", c.usageBuf[1].Metric, "second")
	}
}

func TestUsageReporter_FlushesOnInterval(t *testing.T) {
	var flushCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/tools/usage":
			flushCount.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	store := newMemStore()
	c := newTestClient(t, srv.URL, store)

	c.mu.Lock()
	c.token = &TokenPair{
		AccessToken:  "valid-token",
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		UserID:       "usr-1",
	}
	c.mu.Unlock()

	_ = c.ReportUsage(context.Background(), UsageEvent{Metric: "m1", Value: 1, At: time.Now()})

	reporter := c.StartUsageReporter(context.Background(), 50*time.Millisecond)

	// Wait enough for at least one tick.
	time.Sleep(150 * time.Millisecond)

	reporter.Stop()

	if flushCount.Load() < 1 {
		t.Errorf("expected at least 1 flush, got %d", flushCount.Load())
	}
}

func TestUsageReporter_StopDoesFinalFlush(t *testing.T) {
	var receivedEvents int
	var flushCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/tools/usage":
			flushCount.Add(1)
			var payload usagePayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err == nil {
				receivedEvents += len(payload.Events)
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	store := newMemStore()
	c := newTestClient(t, srv.URL, store)

	c.mu.Lock()
	c.token = &TokenPair{
		AccessToken:  "valid-token",
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		UserID:       "usr-1",
	}
	c.mu.Unlock()

	// Use a long interval so the ticker does not fire.
	reporter := c.StartUsageReporter(context.Background(), 1*time.Hour)

	// Buffer events after starting the reporter.
	_ = c.ReportUsage(context.Background(), UsageEvent{Metric: "final", Value: 42, At: time.Now()})

	// Stop should trigger final flush.
	reporter.Stop()

	// The final flush should have sent the event.
	c.usageMu.Lock()
	bufLen := len(c.usageBuf)
	c.usageMu.Unlock()

	if bufLen != 0 {
		t.Errorf("buffer after Stop = %d, want 0 (final flush should drain buffer)", bufLen)
	}
	if receivedEvents < 1 {
		t.Errorf("received events = %d, want >= 1", receivedEvents)
	}
}
