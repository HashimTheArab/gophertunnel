package request

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/auth/authclient"
	"github.com/sandertv/gophertunnel/minecraft/service"
)

type tokens struct{}

func (tokens) ServiceToken(context.Context) (*service.Token, error) {
	return &service.Token{AuthorizationHeader: "MCToken synthetic", ValidUntil: time.Now().Add(time.Hour)}, nil
}

func serve(t *testing.T, handler http.HandlerFunc) (*http.Client, *url.URL) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	target, _ := url.Parse(server.URL + "/api/v1.0/thing")
	return server.Client(), target
}

// A malformed or missing result is an error, never an empty success.
func TestDoRejectsMalformedResults(t *testing.T) {
	for body, ok := range map[string]bool{`{"result":{"a":1}}`: true, `{"result":null}`: false, `{}`: false, `not json`: false, `{"result":"str"}`: false} {
		client, target := serve(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "MCToken synthetic" {
				t.Errorf("authorization = %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(body))
		})
		var out struct{ A int }
		_, err := Do(context.Background(), client, tokens{}, http.MethodGet, target, nil, &out, Options{})
		if (err == nil) != ok {
			t.Fatalf("%s: err = %v", body, err)
		}
	}
}

// Non-2xx answers become ResponseErrors, and a single-attempt request is never retried.
func TestDoMapsErrorsAndHonoursSingleAttempt(t *testing.T) {
	var calls atomic.Int32
	client, target := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"code":"Busy","message":"try later"}`))
	})
	_, err := Do(context.Background(), client, tokens{}, http.MethodPost, target, struct{}{}, nil, Options{Retry: authclient.RetryOptions{Attempts: 1}})
	var responseErr *service.ResponseError
	if !errors.As(err, &responseErr) || responseErr.StatusCode != http.StatusServiceUnavailable || responseErr.Code != "Busy" {
		t.Fatalf("err = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", calls.Load())
	}
}
