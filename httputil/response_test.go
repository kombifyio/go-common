package httputil

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

var errResponseWrite = errors.New("response write failed")

type failingResponseWriter struct {
	header http.Header
}

func (w *failingResponseWriter) Header() http.Header { return w.header }
func (w *failingResponseWriter) WriteHeader(int)     {}
func (w *failingResponseWriter) Write([]byte) (int, error) {
	return 0, errResponseWrite
}

func TestJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	JSON(w, req, http.StatusOK, map[string]string{"name": "test"})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("unexpected content-type: %s", ct)
	}

	var resp Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.Status != "success" {
		t.Errorf("status = %q, want success", resp.Status)
	}
	if resp.Code != 200 {
		t.Errorf("code = %d, want 200", resp.Code)
	}
	if resp.Meta == nil {
		t.Fatal("meta is nil")
	}
	if resp.Meta.Timestamp == "" {
		t.Error("timestamp is empty")
	}
	if resp.Error != nil {
		t.Error("error should be nil on success")
	}
}

func TestJSONWithRequestID(t *testing.T) {
	handler := RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		JSON(w, r, http.StatusOK, nil)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Request-ID", "test-123")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var resp Response
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.Meta == nil || resp.Meta.RequestID != "test-123" {
		t.Errorf("request_id = %q, want test-123", resp.Meta.RequestID)
	}
}

func TestJSONMessage(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	w := httptest.NewRecorder()

	JSONMessage(w, req, http.StatusCreated, "Resource created", map[string]string{"id": "abc"})

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	var resp Response
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.Message != "Resource created" {
		t.Errorf("message = %q", resp.Message)
	}
}

func TestJSONError(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	JSONError(w, req, http.StatusNotFound, "NOT_FOUND", "Resource not found")

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}

	var resp Response
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.Status != "error" {
		t.Errorf("status = %q, want error", resp.Status)
	}
	if resp.Error == nil {
		t.Fatal("error body is nil")
	}
	if resp.Error.Code != "NOT_FOUND" {
		t.Errorf("error code = %q", resp.Error.Code)
	}
	if resp.Error.Message != "Resource not found" {
		t.Errorf("error message = %q", resp.Error.Message)
	}
	if resp.Data != nil {
		t.Error("data should be nil on error")
	}
}

func TestJSONErrorWithDetails(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	w := httptest.NewRecorder()

	details := map[string]string{"field": "email", "reason": "invalid format"}
	JSONErrorWithDetails(w, req, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid input", details)

	var resp Response
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.Error == nil || resp.Error.Details == nil {
		t.Fatal("error details missing")
	}
}

func TestWriteResponseReportsEncodingFailure(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := &failingResponseWriter{header: make(http.Header)}

	err := writeResponse(w, req, http.StatusOK, "success", "", map[string]string{"ok": "true"}, nil)
	if !errors.Is(err, errResponseWrite) {
		t.Fatalf("writeResponse error = %v, want %v", err, errResponseWrite)
	}
}
