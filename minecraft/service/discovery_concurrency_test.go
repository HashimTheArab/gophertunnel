package service

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/sandertv/gophertunnel/minecraft/auth"
)

// discoveryTransport controls discovery replies without a real network connection.
type discoveryTransport func(*http.Request) (*http.Response, error)

// RoundTrip runs the supplied discovery handler.
func (f discoveryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// isolateDiscoveryCache empties the process-wide discovery cache for the test and again after it.
func isolateDiscoveryCache(t *testing.T) {
	clear := func() {
		discoveryCacheMu.Lock()
		discoveryCache = make(map[string]*Discovery)
		discoveryCacheMu.Unlock()
	}
	clear()
	t.Cleanup(clear)
}

// discoveryOK is a successful, empty discovery reply.
func discoveryOK() *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"result":{"serviceEnvironments":{}}}`))}
}

// Slow discovery must leave cached entries readable and let queued callers cancel.
func TestDiscoveryStallDoesNotBlockCacheOrCancellation(t *testing.T) {
	isolateDiscoveryCache(t)
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

// A caller that cancels must not cancel the shared request for other callers waiting on it.
func TestDiscoveryOwnerCancellationDoesNotFailWaiters(t *testing.T) {
	isolateDiscoveryCache(t)
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		started := make(chan struct{})
		base := auth.WithContextClient(context.Background(), &http.Client{Transport: discoveryTransport(func(r *http.Request) (*http.Response, error) {
			close(started)
			select {
			case <-release:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"result":{"serviceEnvironments":{}}}`))}, nil
		})})
		ownerCtx, cancelOwner := context.WithCancel(base)
		owner := make(chan error, 1)
		go func() { _, err := Discover(ownerCtx, t.Name(), "shared"); owner <- err }()
		<-started
		waiter := make(chan error, 1)
		go func() { _, err := Discover(base, t.Name(), "shared"); waiter <- err }()
		synctest.Wait()
		cancelOwner()
		if err := <-owner; !errors.Is(err, context.Canceled) {
			t.Fatalf("owner error = %v, want context.Canceled", err)
		}
		close(release)
		if err := <-waiter; err != nil {
			t.Fatalf("waiter error after the owner canceled = %v", err)
		}
	})
}

// Callers using different HTTP clients must not share one request, so one client's failure is not another's.
func TestDiscoveryDoesNotShareRequestsAcrossClients(t *testing.T) {
	isolateDiscoveryCache(t)
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		started := make(chan struct{})
		var once sync.Once
		failing := auth.WithContextClient(context.Background(), &http.Client{Transport: discoveryTransport(func(*http.Request) (*http.Response, error) {
			once.Do(func() { close(started) })
			<-release
			return nil, errors.New("proxy unavailable")
		})})
		working := auth.WithContextClient(context.Background(), &http.Client{Transport: discoveryTransport(func(*http.Request) (*http.Response, error) {
			return discoveryOK(), nil
		})})
		failed := make(chan error, 1)
		go func() { _, err := Discover(failing, t.Name(), "shared"); failed <- err }()
		<-started
		if _, err := Discover(working, t.Name(), "shared"); err != nil {
			t.Fatalf("working client got %v", err)
		}
		close(release)
		if err := <-failed; err == nil {
			t.Fatal("failing client unexpectedly succeeded")
		}
	})
}

// Concurrent callers for the same URL share one request, and later callers use its cached result.
func TestDiscoveryMakesOneRequestForConcurrentCallers(t *testing.T) {
	isolateDiscoveryCache(t)
	synctest.Test(t, func(t *testing.T) {
		calls, release := 0, make(chan struct{})
		ctx := auth.WithContextClient(context.Background(), &http.Client{Transport: discoveryTransport(func(*http.Request) (*http.Response, error) {
			calls++
			<-release
			return discoveryOK(), nil
		})})
		errs := make(chan error, 3)
		for range 3 {
			go func() { _, err := Discover(ctx, t.Name(), "test"); errs <- err }()
		}
		synctest.Wait()
		close(release)
		for range 3 {
			if err := <-errs; err != nil {
				t.Fatal(err)
			}
		}
		if _, err := Discover(ctx, t.Name(), "test"); err != nil || calls != 1 {
			t.Fatalf("err = %v, network calls = %d, want 1", err, calls)
		}
	})
}

// Once every caller has stopped waiting, the shared request still finishes within its deadline and fills the cache.
func TestDiscoveryFinishesSharedRequestWithoutWaiters(t *testing.T) {
	isolateDiscoveryCache(t)
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		calls, bounded := 0, false
		base := auth.WithContextClient(context.Background(), &http.Client{Transport: discoveryTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			_, bounded = r.Context().Deadline()
			select {
			case <-release:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
			return discoveryOK(), nil
		})})
		first, cancelFirst := context.WithCancel(base)
		second, cancelSecond := context.WithCancel(base)
		errs := make(chan error, 2)
		go func() { _, err := Discover(first, t.Name(), "test"); errs <- err }()
		go func() { _, err := Discover(second, t.Name(), "test"); errs <- err }()
		synctest.Wait()
		cancelFirst()
		cancelSecond()
		for range 2 {
			if err := <-errs; !errors.Is(err, context.Canceled) {
				t.Fatalf("caller error = %v", err)
			}
		}
		close(release)
		synctest.Wait()
		if _, err := Discover(base, t.Name(), "test"); err != nil || calls != 1 || !bounded {
			t.Fatalf("err = %v, network calls = %d, want 1; request bounded = %v", err, calls, bounded)
		}
	})
}
