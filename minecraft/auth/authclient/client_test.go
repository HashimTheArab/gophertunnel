package authclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestSendRequestWithRetriesRetriesTransientStatus(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := SendRequestWithRetries(context.Background(), server.Client(), req, RetryOptions{
		Attempts: 2,
		MinDelay: time.Millisecond,
		MaxDelay: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if got := attempts.Load(); got != 2 {
		t.Fatalf("attempts mismatch: got %d want 2", got)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status mismatch: got %d", resp.StatusCode)
	}
}
