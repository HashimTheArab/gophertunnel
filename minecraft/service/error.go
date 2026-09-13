package service

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	maxResponseErrorBody = 64 << 10
	maxDiagnosticBody    = 512
)

// ResponseError is an error response returned by a Minecraft service.
//
// Callers may use [errors.As] to inspect the service-specific fields and the
// HTTP request which produced the response. CustomData is service-specific JSON
// and may be nil.
type ResponseError struct {
	// Namespace identifies the service namespace which returned the error.
	Namespace string `json:"namespace"`
	// Code identifies the error within Namespace.
	Code string `json:"code"`
	// Message is the human-readable service error message.
	Message string `json:"message"`
	// CustomData contains service-specific error details.
	CustomData json.RawMessage `json:"customData"`

	// StatusCode is the HTTP response status code.
	StatusCode int `json:"-"`
	// Status is the HTTP response status, such as "401 Unauthorized".
	Status string `json:"-"`
	// Method is the HTTP request method, when the response contains a request.
	Method string `json:"-"`
	// URL is the HTTP request URL, when the response contains a request.
	URL string `json:"-"`

	body       string
	structured bool
}

// Error returns a description containing both the service error and its HTTP
// context.
func (e *ResponseError) Error() string {
	var detail string
	if e.structured {
		detail = fmt.Sprintf("%s: %q (%s)", e.Code, e.Message, e.Namespace)
	} else if e.body != "" {
		detail = fmt.Sprintf("%q", e.body)
	}

	context := strings.TrimSpace(strings.Join([]string{e.Method, e.URL, e.Status}, " "))
	switch {
	case context != "" && detail != "":
		return "minecraft/service: " + detail + ": " + context
	case detail != "":
		return "minecraft/service: " + detail
	case context != "":
		return "minecraft/service: " + context
	default:
		return "minecraft/service: error response"
	}
}

// NewResponseError consumes resp.Body and returns a structured error for an
// unsuccessful Minecraft service response. The response body is bounded to
// avoid retaining an unbounded error payload.
func NewResponseError(resp *http.Response) *ResponseError {
	e := new(ResponseError)
	if resp == nil {
		return e
	}
	e.StatusCode, e.Status = resp.StatusCode, resp.Status
	if resp.Request != nil {
		e.Method = resp.Request.Method
		if resp.Request.URL != nil {
			e.URL = resp.Request.URL.String()
		}
	}
	if resp.Body == nil {
		return e
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseErrorBody))
	e.structured = json.Unmarshal(body, e) == nil &&
		(e.Namespace != "" || e.Code != "" || e.Message != "" || len(e.CustomData) != 0)
	if !e.structured && len(body) != 0 {
		if len(body) > maxDiagnosticBody {
			body = body[:maxDiagnosticBody]
		}
		e.body = string(body)
	}
	return e
}
