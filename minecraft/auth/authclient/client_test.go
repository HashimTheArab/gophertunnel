package authclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestSendRequestWithRetriesKeepsFinalTransientBodyOpen(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("service unavailable"))
	}))
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := SendRequestWithRetries(context.Background(), server.Client(), req, RetryOptions{
		Attempts: 1,
		MinDelay: time.Millisecond,
		MaxDelay: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read final response body: %v", err)
	}
	if string(body) != "service unavailable" {
		t.Fatalf("body mismatch: got %q", body)
	}
}

func TestSendRequestWithRetriesDoesNotRetryNonRewindableBody(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("try later"))
	}))
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL, io.NopCloser(strings.NewReader("payload")))
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

	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts mismatch: got %d want 1", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read final response body: %v", err)
	}
	if string(body) != "try later" {
		t.Fatalf("body mismatch: got %q", body)
	}
}
