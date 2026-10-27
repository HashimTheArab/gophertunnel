package internal

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/sandertv/gophertunnel/minecraft/auth/authclient"
)

// requestTransport supplies HTTP responses without making network connections.
type requestTransport func(*http.Request) (*http.Response, error)

// RoundTrip runs the test's HTTP handler.
func (f requestTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// prepareRequest creates a replayable POST so tests can check retries preserve its body.
func prepareRequest(ctx context.Context) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, http.MethodPost, "https://service.test", strings.NewReader("payload"))
}

// requestResponse returns an empty successful response.
func requestResponse() *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}
}

func TestSendRequestRetriesWithinBounds(t *testing.T) {
	for _, test := range []struct {
		name     string
		timeout  time.Duration
		opts     RequestOptions
		expected time.Duration
	}{
		{name: "defaults", expected: CatalogRequestTimeout},
		{name: "shorter client", timeout: time.Second, expected: time.Second},
		{name: "clamped client", timeout: time.Hour, expected: CatalogRequestTimeout},
		{name: "override", opts: RequestOptions{RequestTimeout: 2 * time.Second}, expected: 2 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				calls := 0
				started := time.Now()
				client := &http.Client{Timeout: test.timeout, Transport: requestTransport(func(req *http.Request) (*http.Response, error) {
					calls++
					body, err := io.ReadAll(req.Body)
					if err != nil || string(body) != "payload" {
						t.Fatalf("body = %q, err = %v", body, err)
					}
					if calls == 1 {
						<-req.Context().Done()
						if elapsed := time.Since(started); elapsed != test.expected {
							t.Errorf("attempt elapsed = %v, want %v", elapsed, test.expected)
						}
						return nil, req.Context().Err()
					}
					return requestResponse(), nil
				})}
				resp, err := SendRequest(auth.WithContextClient(context.Background(), client), nil, prepareRequest, test.opts)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if calls != CatalogRequestAttempts || client.Timeout != test.timeout {
					t.Fatalf("calls = %d, caller timeout = %v", calls, client.Timeout)
				}
			})
		})
	}
}

func TestSendRequestBoundsPreparation(t *testing.T) {
	for _, timeout := range []time.Duration{0, time.Second} {
		synctest.Test(t, func(t *testing.T) {
			started := time.Now()
			_, err := SendRequest(context.Background(), nil, func(ctx context.Context) (*http.Request, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			}, RequestOptions{CallTimeout: timeout})
			want := timeout
			if want == 0 {
				want = CatalogCallTimeout
			}
			if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) != want {
				t.Fatalf("err = %v, elapsed = %v, want %v", err, time.Since(started), want)
			}
		})
	}
}

// stalledBody waits for the request context, modelling a stalled response stream.
type stalledBody struct{ ctx context.Context }

// Read waits until the service call's deadline or cancellation.
func (b stalledBody) Read([]byte) (int, error) { <-b.ctx.Done(); return 0, b.ctx.Err() }

// Close has no resources to release in this test stream.
func (stalledBody) Close() error { return nil }

func TestSendRequestBoundsResponseBody(t *testing.T) {
	for _, test := range []struct {
		name string
		opts RequestOptions
		want time.Duration
	}{
		{name: "call deadline", opts: RequestOptions{CallTimeout: time.Second}, want: time.Second},
		{name: "attempt timeout", want: CatalogRequestTimeout},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client := &http.Client{Transport: requestTransport(func(req *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: http.StatusOK, Body: stalledBody{ctx: req.Context()}}, nil
				})}
				started := time.Now()
				resp, err := SendRequest(context.Background(), client, prepareRequest, test.opts)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				if _, err := io.ReadAll(resp.Body); !errors.Is(err, context.DeadlineExceeded) || time.Since(started) != test.want {
					t.Fatalf("read err = %v, elapsed = %v", err, time.Since(started))
				}
			})
		})
	}
}

func TestSendRequestReleasesContextOnClose(t *testing.T) {
	var requestCtx context.Context
	client := &http.Client{Transport: requestTransport(func(req *http.Request) (*http.Response, error) {
		requestCtx = req.Context()
		return requestResponse(), nil
	})}
	resp, err := SendRequest(context.Background(), client, prepareRequest, RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if requestCtx.Err() != nil {
		t.Fatal("request context was cancelled before the body was closed")
	}
	resp.Body.Close()
	if !errors.Is(requestCtx.Err(), context.Canceled) {
		t.Fatalf("context after closing body = %v", requestCtx.Err())
	}
}

func TestSendRequestPreservesRetryPolicy(t *testing.T) {
	for _, test := range []struct {
		status   int
		attempts int
		want     int
	}{
		{status: http.StatusUnauthorized, want: 1},
		{status: http.StatusServiceUnavailable, want: CatalogRequestAttempts},
		{status: http.StatusServiceUnavailable, attempts: 1, want: 1},
		{status: http.StatusServiceUnavailable, attempts: 4, want: 4},
	} {
		synctest.Test(t, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: requestTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				resp := requestResponse()
				resp.StatusCode = test.status
				return resp, nil
			})}
			resp, err := SendRequest(context.Background(), client, prepareRequest, RequestOptions{Retry: authclient.RetryOptions{Attempts: test.attempts}})
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if calls != test.want || resp.StatusCode != test.status {
				t.Fatalf("calls = %d, want %d; status = %d", calls, test.want, resp.StatusCode)
			}
		})
	}
}

func TestSendRequestHonorsCancellation(t *testing.T) {
	for _, alreadyCancelled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		client := &http.Client{Transport: requestTransport(func(req *http.Request) (*http.Response, error) {
			calls++
			cancel()
			return nil, req.Context().Err()
		})}
		if alreadyCancelled {
			cancel()
		}
		_, err := SendRequest(ctx, client, prepareRequest, RequestOptions{})
		cancel()
		want := 1
		if alreadyCancelled {
			want = 0
		}
		if !errors.Is(err, context.Canceled) || calls != want {
			t.Fatalf("err = %v, calls = %d, want %d", err, calls, want)
		}
	}
}
