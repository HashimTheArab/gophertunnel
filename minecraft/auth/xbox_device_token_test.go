package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

type mockDeviceAuthTransport struct {
	delay time.Duration

	mu    sync.Mutex
	calls int
}

func (m *mockDeviceAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()

	if m.delay > 0 {
		timer := time.NewTimer(m.delay)
		defer timer.Stop()
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-timer.C:
		}
	}

	body := fmt.Sprintf(
		`{"IssueInstant":"%s","NotAfter":"%s","Token":"device-token"}`,
		time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano),
		time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
	)

	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

func (m *mockDeviceAuthTransport) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func authCtxWithClient(rt http.RoundTripper) context.Context {
	return context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
		Transport: rt,
		Timeout:   5 * time.Second,
	})
}

func waitForTransportCalls(t *testing.T, rt *mockDeviceAuthTransport, want int, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if rt.Calls() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d transport calls, got %d", want, rt.Calls())
}

func TestXBLTokenCache_deviceToken_DeduplicatesConcurrentRequests(t *testing.T) {
	cache := AndroidConfig.NewTokenCache()
	transport := &mockDeviceAuthTransport{delay: 80 * time.Millisecond}
	ctx := authCtxWithClient(transport)

	const workers = 10

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		toks []*deviceToken
	)

	errs := make(chan error, workers)
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()

			tok, err := cache.deviceToken(ctx, AndroidConfig)
			if err != nil {
				errs <- err
				return
			}
			mu.Lock()
			toks = append(toks, tok)
			mu.Unlock()
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatalf("deviceToken returned error: %v", err)
	}
	if got := transport.Calls(); got != 1 {
		t.Fatalf("expected exactly 1 device-auth request, got %d", got)
	}
	if len(toks) != workers {
		t.Fatalf("expected %d tokens, got %d", workers, len(toks))
	}

	first := toks[0]
	for i := 1; i < len(toks); i++ {
		if toks[i] != first {
			t.Fatalf("expected all goroutines to share one cached token pointer")
		}
	}
}

func TestXBLTokenCache_deviceToken_WaiterContextCancellation(t *testing.T) {
	cache := AndroidConfig.NewTokenCache()
	transport := &mockDeviceAuthTransport{delay: 200 * time.Millisecond}
	baseCtx := authCtxWithClient(transport)

	leaderErr := make(chan error, 1)
	go func() {
		_, err := cache.deviceToken(baseCtx, AndroidConfig)
		leaderErr <- err
	}()

	waitForTransportCalls(t, transport, 1, time.Second)

	waiterCtx, cancel := context.WithTimeout(baseCtx, 30*time.Millisecond)
	defer cancel()

	_, err := cache.deviceToken(waiterCtx, AndroidConfig)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected waiter context deadline exceeded, got %v", err)
	}

	if err := <-leaderErr; err != nil {
		t.Fatalf("leader deviceToken call failed: %v", err)
	}
	if got := transport.Calls(); got != 1 {
		t.Fatalf("expected exactly 1 device-auth request, got %d", got)
	}

	// Token should now be cached; this call should not trigger another HTTP request.
	if _, err := cache.deviceToken(baseCtx, AndroidConfig); err != nil {
		t.Fatalf("cached deviceToken call failed: %v", err)
	}
	if got := transport.Calls(); got != 1 {
		t.Fatalf("expected no additional device-auth requests after caching, got %d", got)
	}
}
