package minecraft

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/sandertv/gophertunnel/minecraft/service"
	"golang.org/x/oauth2"
)

// issuerServer serves an OpenID configuration and one signing key, as the authorization service does.
func issuerServer(t *testing.T) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint := sha1.Sum(key.N.Bytes())
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": server.URL, "jwks_uri": server.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/keys":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k", Algorithm: "RS256", Use: "sig", CertificateThumbprintSHA1: thumbprint[:]}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// discoveryWithIssuer returns a Discovery whose auth service is issuer.
func discoveryWithIssuer(t *testing.T, issuer string) *service.Discovery {
	t.Helper()
	auth, err := json.Marshal(map[string]any{"serviceUri": issuer, "issuer": issuer, "playfabTitleId": "20CA2"})
	if err != nil {
		t.Fatal(err)
	}
	return &service.Discovery{ServiceEnvironments: map[string]map[string]json.RawMessage{"auth": {"prod": auth}}}
}

// The authorization environment follows discovery, and swaps to a moved issuer only once its verifier is ready.
func TestAuthEnvFollowsDiscovery(t *testing.T) {
	first, moved := issuerServer(t), issuerServer(t)
	current := discoveryWithIssuer(t, first.URL)
	var discoverErr error
	oldDiscover := authEnvDiscover
	authEnvDiscover = func(context.Context) (*service.Discovery, error) { return current, discoverErr }
	resetAuthState()
	t.Cleanup(func() {
		authEnvDiscover = oldDiscover
		resetAuthState()
	})
	ctx := context.Background()
	client := &http.Client{}

	initial, err := authEnv(context.WithValue(ctx, oauth2.HTTPClient, client))
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := authEnv(ctx); e != initial {
		t.Fatal("same discovery: environment replaced")
	}
	current = discoveryWithIssuer(t, first.URL)
	if e, _ := authEnv(ctx); e != initial {
		t.Fatal("refreshed discovery with the same issuer: environment replaced")
	}

	current = discoveryWithIssuer(t, moved.URL)
	if e, _ := authEnv(ctx); e != initial {
		t.Fatal("moved issuer: environment replaced before its verifier was ready")
	}
	deadline := time.Now().Add(5 * time.Second)
	var swapped *service.AuthorizationEnvironment
	for time.Now().Before(deadline) {
		if e, _ := authEnv(ctx); e != initial {
			swapped = e
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if swapped == nil || swapped.Issuer.String() != moved.URL {
		t.Fatalf("moved issuer: environment = %v, want issuer %s", swapped, moved.URL)
	}
	if _, err := swapped.VerifierContext(ctx); err != nil {
		t.Fatalf("swapped environment has no verifier: %v", err)
	}
	if swapped.HTTPClient != client {
		t.Fatal("swapped environment lost the first caller's HTTP client")
	}

	discoverErr = errors.New("discovery unavailable")
	if e, err := authEnv(ctx); err != nil || e != swapped {
		t.Fatalf("failed discovery: error = %v, kept environment = %v", err, e == swapped)
	}
}

// Concurrent first calls share one authorization environment.
func TestAuthEnvColdCallsShareOneEnvironment(t *testing.T) {
	server := issuerServer(t)
	d := discoveryWithIssuer(t, server.URL)
	oldDiscover := authEnvDiscover
	authEnvDiscover = func(context.Context) (*service.Discovery, error) { return d, nil }
	resetAuthState()
	t.Cleanup(func() {
		authEnvDiscover = oldDiscover
		resetAuthState()
	})
	envs := make(chan *service.AuthorizationEnvironment, 8)
	for range 8 {
		go func() {
			e, _ := authEnv(context.Background())
			envs <- e
		}()
	}
	first := <-envs
	for range 7 {
		if e := <-envs; e != first || e == nil {
			t.Fatal("concurrent first calls returned different environments")
		}
	}
}

// resetAuthState empties the authorization environment authEnv maintains.
func resetAuthState() {
	authState.Lock()
	defer authState.Unlock()
	authState.env, authState.discovery, authState.pending, authState.retryAt = nil, nil, false, time.Time{}
}
