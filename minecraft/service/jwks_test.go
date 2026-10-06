package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
