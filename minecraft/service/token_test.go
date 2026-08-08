package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type serviceRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f serviceRoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestTokenUsesServiceResponseTime(t *testing.T) {
	serverTime := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	validUntil := serverTime.Add(10 * time.Minute)
	claims := map[string]any{
		"exp":  validUntil.Unix(),
		"pmid": uuid.NewString(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	token := Token{
		AuthorizationHeader: "MCToken e30." + base64.RawURLEncoding.EncodeToString(payload) + ".signature",
		ValidUntil:          validUntil,
	}
	body, err := json.Marshal(map[string]any{"result": token})
	if err != nil {
		t.Fatal(err)
	}

	env := testAuthorizationEnvironment(t, func(req *http.Request) (*http.Response, error) {
		return serviceResponse(req, serverTime, string(body)), nil
	})
	got, err := env.Token(context.Background(), TokenConfig{User: UserConfig{Token: "ticket"}})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Valid() {
		t.Fatal("Token.Valid() = false, want true using retained service response time")
	}
}

func TestRenewRejectsNilTokenResult(t *testing.T) {
	env := testAuthorizationEnvironment(t, func(req *http.Request) (*http.Response, error) {
		return serviceResponse(req, time.Now(), `{"result":null}`), nil
	})

	_, err := env.Renew(context.Background(), &Token{AuthorizationHeader: "old"}, UserConfig{Token: "ticket"})
	if err == nil {
		t.Fatal("Renew returned nil error for a nil token result")
	}
	if !strings.Contains(err.Error(), "invalid renew token result") {
		t.Fatalf("Renew error = %q, want invalid token result", err)
	}
}

func testAuthorizationEnvironment(t *testing.T, roundTrip serviceRoundTripperFunc) *AuthorizationEnvironment {
	t.Helper()
	serviceURI, err := url.Parse("https://example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	return &AuthorizationEnvironment{
		ServiceURI: serviceURI,
		HTTPClient: &http.Client{Transport: roundTrip},
	}
}

func serviceResponse(req *http.Request, date time.Time, body string) *http.Response {
	return &http.Response{
		StatusCode:    http.StatusOK,
		Status:        "200 OK",
		Header:        http.Header{"Date": []string{date.UTC().Format(http.TimeFormat)}, "Content-Length": []string{strconv.Itoa(len(body))}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}
