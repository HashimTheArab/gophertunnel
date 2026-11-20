package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

// A preloaded verifier needs no configuration or key fetch at verification time.
func TestPreloadVerifierFetchesConfigurationAndKeysOnce(t *testing.T) {
	encoded := testJWK(t)
	var configurations, keys atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			configurations.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": server.URL, "jwks_uri": server.URL + "/keys", "id_token_signing_alg_values_supported": []string{"ES256"}})
		case "/keys":
			keys.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{encoded}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer, _ := url.Parse(server.URL)
	env := &AuthorizationEnvironment{Issuer: issuer, HTTPClient: server.Client()}
	for range 2 {
		if err := env.PreloadVerifier(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if cached, _ := env.keySet.keysFromCache(); len(cached) != 1 || configurations.Load() != 1 || keys.Load() != 1 {
		t.Fatalf("keys=%d configuration fetches=%d key fetches=%d, want 1 each", len(cached), configurations.Load(), keys.Load())
	}
}

// Concurrent verifier builds share one configuration fetch, and a caller stops waiting at its own deadline.
func TestVerifierContextSharesConfigurationFetch(t *testing.T) {
	gate := make(chan struct{})
	var configurations atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		if configurations.Add(1) > 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		<-gate
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": server.URL, "jwks_uri": server.URL + "/keys", "id_token_signing_alg_values_supported": []string{"ES256"}})
	}))
	defer server.Close()
	issuer, _ := url.Parse(server.URL)
	env := &AuthorizationEnvironment{Issuer: issuer, HTTPClient: server.Client()}

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := env.VerifierContext(ctx); err == nil {
		t.Fatal("VerifierContext succeeded while the configuration was held")
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("VerifierContext waited %v past a 200ms deadline", waited)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			_, err := env.VerifierContext(t.Context())
			errs <- err
		})
	}
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := configurations.Load(); n != 1 {
		t.Fatalf("configuration fetches = %d, want 1", n)
	}
}

// A build started by a caller that found no verifier returns one cached since, without fetching again.
func TestBuildVerifierReturnsVerifierCachedSince(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()
	issuer, _ := url.Parse(server.URL)
	cached := &oidc.IDTokenVerifier{}
	env := &AuthorizationEnvironment{Issuer: issuer, HTTPClient: server.Client(), verifier: cached}
	got, err := env.buildVerifier(t.Context())
	if err != nil || got != cached || requests.Load() != 0 {
		t.Fatalf("buildVerifier = %p, %v after %d requests; want the cached verifier and no request", got, err, requests.Load())
	}
}

// A refresh must publish its keys to the cache before its waiters return.
func TestKeysFromRemotePublishesCacheBeforeReturning(t *testing.T) {
	encoded := testJWK(t)
	requested, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requested)
		<-release
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{encoded}})
	}))
	defer server.Close()
	set := newRefreshingKeySet(t.Context(), &AuthorizationEnvironment{HTTPClient: server.Client()}, server.URL, time.Hour, []string{"ES256"})
	done := make(chan error, 1)
	go func() {
		_, err := set.keysFromRemote(t.Context())
		done <- err
	}()
	<-requested
	// Publication needs the write lock, so holding the read lock keeps a correct refresh from completing.
	set.mu.RLock()
	close(release)
	select {
	case <-done:
		set.mu.RUnlock()
		t.Fatal("keysFromRemote returned before publishing the fetched keys")
	case <-time.After(100 * time.Millisecond):
	}
	set.mu.RUnlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if cached, _ := set.keysFromCache(); len(cached) != 1 {
		t.Fatalf("cached keys = %d after refresh, want 1", len(cached))
	}
}

// testJWK returns a public ES256 signing key in the JWKS form the authorization service serves.
func testJWK(t *testing.T) map[string]any {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := jose.JSONWebKey{Key: key.Public(), KeyID: "kid", Algorithm: "ES256", Use: "sig"}.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var encoded map[string]any
	if err := json.Unmarshal(jwk, &encoded); err != nil {
		t.Fatal(err)
	}
	encoded["x5t"] = strings.Repeat("ab", 20)
	return encoded
}
