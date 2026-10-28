package gatherings

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/df-mc/go-playfab/v2/catalog"
	"github.com/sandertv/gophertunnel/minecraft/auth/authclient"
)

// searchTransport lets tests stall one request without a real network connection.
type searchTransport func(*http.Request) (*http.Response, error)

// RoundTrip runs the test's response handler.
func (f searchTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A stalled search request ends at the call deadline instead of waiting for the caller's longer one.
func TestSearchItemsStalledRequestEndsAtCallDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		client := (&Environment{ServiceURI: &url.URL{Scheme: "https", Host: "gatherings.test"}, HTTPClient: &http.Client{Transport: searchTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			<-r.Context().Done()
			return nil, r.Context().Err()
		})}}).New(fixedTokens{})
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		started := time.Now()
		_, err := client.SearchItems(ctx, catalog.SearchFilter{Filter: "test filter"})
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) != authclient.DefaultCallTimeout || calls != 1 {
			t.Fatalf("err = %v, elapsed = %v, calls = %d", err, time.Since(started), calls)
		}
	})
}

// A caller cancellation stops a request without starting another attempt.
func TestSearchItemsHonorsCallerCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		client := (&Environment{ServiceURI: &url.URL{Scheme: "https", Host: "gatherings.test"}, HTTPClient: &http.Client{Transport: searchTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			cancel()
			<-r.Context().Done()
			return nil, r.Context().Err()
		})}}).New(fixedTokens{})
		if _, err := client.SearchItems(ctx, catalog.SearchFilter{}); !errors.Is(err, context.Canceled) || calls != 1 {
			t.Fatalf("err = %v, calls = %d", err, calls)
		}
	})
}

// Permanent refusals are returned without retrying a catalog request.
func TestSearchItemsDoesNotRetryPermanentFailure(t *testing.T) {
	calls := 0
	client := (&Environment{ServiceURI: &url.URL{Scheme: "https", Host: "gatherings.test"}, HTTPClient: &http.Client{Transport: searchTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}}).New(fixedTokens{})
	if _, err := client.SearchItems(context.Background(), catalog.SearchFilter{}); err == nil || calls != 1 {
		t.Fatalf("err = %v, calls = %d", err, calls)
	}
}
