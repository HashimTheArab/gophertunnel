package service_test

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/service"
)

func TestNewResponseErrorStructured(t *testing.T) {
	reqURL, err := url.Parse("https://example.com/api/token")
	if err != nil {
		t.Fatal(err)
	}
	resp := &http.Response{
		Status:     "401 Unauthorized",
		StatusCode: http.StatusUnauthorized,
		Request:    &http.Request{Method: http.MethodPost, URL: reqURL},
		Body: io.NopCloser(strings.NewReader(`{
			"namespace":"auth",
			"code":"InvalidToken",
			"message":"The token expired",
			"customData":{"retryAfter":30}
		}`)),
	}

	returned := error(service.NewResponseError(resp))
	var responseErr *service.ResponseError
	if !errors.As(returned, &responseErr) {
		t.Fatalf("errors.As(error, *service.ResponseError) = false for %T", returned)
	}
	if got, want := responseErr.Namespace, "auth"; got != want {
		t.Fatalf("Namespace = %q, want %q", got, want)
	}
	if got, want := responseErr.Code, "InvalidToken"; got != want {
		t.Fatalf("Code = %q, want %q", got, want)
	}
	if got, want := responseErr.Message, "The token expired"; got != want {
		t.Fatalf("Message = %q, want %q", got, want)
	}
	if got, want := string(responseErr.CustomData), `{"retryAfter":30}`; got != want {
		t.Fatalf("CustomData = %s, want %s", got, want)
	}
	if got, want := responseErr.StatusCode, http.StatusUnauthorized; got != want {
		t.Fatalf("StatusCode = %d, want %d", got, want)
	}
	if got, want := responseErr.Method, http.MethodPost; got != want {
		t.Fatalf("Method = %q, want %q", got, want)
	}
	if got, want := responseErr.URL, reqURL.String(); got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
	for _, part := range []string{"POST", reqURL.String(), "401 Unauthorized", "InvalidToken", "The token expired", "auth"} {
		if !strings.Contains(responseErr.Error(), part) {
			t.Errorf("Error() = %q, want it to contain %q", responseErr.Error(), part)
		}
	}
}

func TestNewResponseErrorMalformedBody(t *testing.T) {
	resp := &http.Response{
		Status:     "502 Bad Gateway",
		StatusCode: http.StatusBadGateway,
		Body:       io.NopCloser(strings.NewReader("upstream unavailable")),
	}

	err := service.NewResponseError(resp)
	if got, want := err.StatusCode, http.StatusBadGateway; got != want {
		t.Fatalf("StatusCode = %d, want %d", got, want)
	}
	if got := err.Error(); !strings.Contains(got, "upstream unavailable") {
		t.Fatalf("Error() = %q, want malformed response body", got)
	}
}
