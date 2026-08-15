package httputil

import (
	"encoding/json"
	"net/http"
	"time"
)

// Response is the standard API response envelope defined in API-FIRST-STANDARD.md.
//
// All kombify API endpoints SHOULD use this envelope for consistency.
// Exceptions: SSE streams, file downloads, health checks (plain 200 OK).
type Response struct {
	Status  string      `json:"status"`
	Code    int         `json:"code"`
	Message string      `json:"message,omitempty"`
	Data    any         `json:"data,omitempty"`
	Meta    *Meta       `json:"meta,omitempty"`
	Error   *ErrorBody  `json:"error,omitempty"`
}

// Meta carries request metadata in the response envelope.
type Meta struct {
	RequestID string `json:"request_id,omitempty"`
	Timestamp string `json:"timestamp"`
}

// ErrorBody carries structured error details.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

// PaginationMeta extends data with pagination info for collection endpoints.
type PaginationMeta struct {
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// JSON writes a success response with the standard envelope.
func JSON(w http.ResponseWriter, r *http.Request, code int, data any) {
	// The compatibility API has no error channel after response headers begin.
	_ = writeResponse(w, r, code, "success", "", data, nil)
}

// JSONMessage writes a success response with a message and optional data.
func JSONMessage(w http.ResponseWriter, r *http.Request, code int, message string, data any) {
	// The compatibility API has no error channel after response headers begin.
	_ = writeResponse(w, r, code, "success", message, data, nil)
}

// JSONError writes an error response with the standard envelope.
func JSONError(w http.ResponseWriter, r *http.Request, httpCode int, errCode string, message string) {
	// The compatibility API has no error channel after response headers begin.
	_ = writeResponse(w, r, httpCode, "error", "", nil, &ErrorBody{
		Code:    errCode,
		Message: message,
	})
}

// JSONErrorWithDetails writes an error response with additional details.
func JSONErrorWithDetails(w http.ResponseWriter, r *http.Request, httpCode int, errCode string, message string, details any) {
	// The compatibility API has no error channel after response headers begin.
	_ = writeResponse(w, r, httpCode, "error", "", nil, &ErrorBody{
		Code:    errCode,
		Message: message,
		Details: details,
	})
}

func writeResponse(w http.ResponseWriter, r *http.Request, code int, status string, message string, data any, errBody *ErrorBody) error {
	resp := Response{
		Status:  status,
		Code:    code,
		Message: message,
		Data:    data,
		Error:   errBody,
		Meta: &Meta{
			RequestID: GetRequestID(r.Context()),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	return json.NewEncoder(w).Encode(resp)
}
