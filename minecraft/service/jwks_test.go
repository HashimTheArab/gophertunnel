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

	"github.com/go-jose/go-jose/v4"
)

// A preloaded verifier needs no configuration or key fetch at verification time.
func TestPreloadVerifierFetchesConfigurationAndKeysOnce(t *testing.T) {
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
