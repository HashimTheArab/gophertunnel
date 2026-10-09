package service

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/sandertv/gophertunnel/minecraft/auth"
)

// discoveryTransport controls discovery replies without a real network connection.
type discoveryTransport func(*http.Request) (*http.Response, error)

// RoundTrip runs the supplied discovery handler.
func (f discoveryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Slow discovery must leave cached entries readable and let queued callers cancel.
func TestDiscoveryStallDoesNotBlockCacheOrCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		started := make(chan struct{})
		ctx := auth.WithContextClient(context.Background(), &http.Client{Transport: discoveryTransport(func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "/slow") {
				close(started)
				<-release
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"result":{"serviceEnvironments":{}}}`))}, nil
		})})
		if _, err := Discover(ctx, t.Name(), "cached"); err != nil {
			t.Fatal(err)
		}
		owner := make(chan struct{})
		go func() { _, _ = Discover(ctx, t.Name(), "slow"); close(owner) }()
		<-started
		cached := make(chan error, 1)
		go func() { _, err := Discover(ctx, t.Name(), "cached"); cached <- err }()
		wait, cancel := context.WithCancel(ctx)
		canceled := make(chan error, 1)
		go func() { _, err := Discover(wait, t.Name(), "slow"); canceled <- err }()
		synctest.Wait()
		cancel()
		synctest.Wait()
		cacheReady, cancelReady := len(cached) == 1, len(canceled) == 1
		close(release)
		<-owner
		if err := <-cached; err != nil {
			t.Fatal(err)
		}
		if err := <-canceled; !errors.Is(err, context.Canceled) {
			t.Errorf("queued request error = %v", err)
		}
		if !cacheReady || !cancelReady {
			t.Fatalf("before release: cached ready = %v, canceled ready = %v", cacheReady, cancelReady)
		}
	})
}
