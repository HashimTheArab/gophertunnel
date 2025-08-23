package auth

import (
	"fmt"
	"net/http"
	"strings"
)

// XboxError represents a structured error from Xbox Live authentication.
type XboxError struct {
	// URL is the endpoint that was called when the error occurred
	URL string
	// Method is the HTTP method used (usually POST)
	Method string
	// StatusCode is the HTTP status code returned (if any)
	StatusCode int
	// Status is the HTTP status text
	Status string
	// XboxErrorCode is the custom error code from the x-err header
	XboxErrorCode string
	// ResponseBody contains the raw response body for debugging
	ResponseBody string
	// Underlying is the underlying error that caused this (network errors, etc.)
	Underlying error
}

// Error implements the error interface.
func (e *XboxError) Error() string {
	var parts []string

	if e.Method != "" && e.URL != "" {
		parts = append(parts, fmt.Sprintf("%s %s", e.Method, e.URL))
	}

	if e.XboxErrorCode != "" {
		// Use the parsed error message for Xbox-specific errors
		parts = append(parts, parseXboxErrorCode(e.XboxErrorCode))
	} else if e.StatusCode != 0 {
		parts = append(parts, fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Status))
	}

	if e.Underlying != nil {
		parts = append(parts, e.Underlying.Error())
	}

	return strings.Join(parts, ": ")
}

// Unwrap returns the underlying error for error unwrapping.
func (e *XboxError) Unwrap() error {
	return e.Underlying
}

// IsNetworkError returns true if this error was caused by a network issue.
func (e *XboxError) IsNetworkError() bool {
	return e.Underlying != nil && e.StatusCode == 0
}

// IsXboxSpecificError returns true if this is a known Xbox Live error code.
func (e *XboxError) IsXboxSpecificError() bool {
	return e.XboxErrorCode != ""
}

// GetParsedXboxError returns the human-readable Xbox error message if available.
func (e *XboxError) GetParsedXboxError() string {
	if e.XboxErrorCode == "" {
		return ""
	}
	return parseXboxErrorCode(e.XboxErrorCode)
}

// newXboxError creates a new XboxError for network-related failures.
func newXboxNetworkError(method, url string, err error, responseBody []byte) *XboxError {
	return &XboxError{
		Method:       method,
		URL:          url,
		Underlying:   err,
		ResponseBody: string(responseBody),
	}
}

// newXboxHTTPError creates a new XboxError for HTTP response errors.
func newXboxHTTPError(method, url string, resp *http.Response, responseBody []byte) *XboxError {
	xboxErr := &XboxError{
		Method:       method,
		URL:          url,
		StatusCode:   resp.StatusCode,
		Status:       resp.Status,
		ResponseBody: string(responseBody),
	}

	// Check for Xbox-specific error code in headers
	if errorCode := resp.Header.Get("x-err"); errorCode != "" {
		xboxErr.XboxErrorCode = errorCode
	}

	return xboxErr
}
