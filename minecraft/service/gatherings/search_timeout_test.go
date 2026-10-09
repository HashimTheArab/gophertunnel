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
)

// searchTransport lets tests stall one request without a real network connection.
type searchTransport func(*http.Request) (*http.Response, error)

// RoundTrip runs the test's response handler.
func (f searchTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// searchResponse returns a minimal successful catalog response.
func searchResponse() *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"data":{"Items":[]}}`))}
}

// A stalled catalog request expires independently and the next attempt succeeds.
func TestSearchItemsRetriesStalledRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		client := (&Environment{ServiceURI: &url.URL{Scheme: "https", Host: "gatherings.test"}, HTTPClient: &http.Client{Transport: searchTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			body, err := io.ReadAll(r.Body)
			if err != nil || !strings.Contains(string(body), "test filter") {
				t.Errorf("retry lost request body: %q, %v", body, err)
			}
			if calls == 1 {
				<-r.Context().Done()
				return nil, r.Context().Err()
			}
			return searchResponse(), nil
		})}}).New(fixedTokens{})
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		result, err := client.SearchItems(ctx, catalog.SearchFilter{Filter: "test filter"})
		if err != nil || result == nil || calls != 2 {
			t.Fatalf("result = %v, err = %v, calls = %d", result, err, calls)
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
