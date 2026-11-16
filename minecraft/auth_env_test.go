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
	return issuerServerWith(t, nil, true)
}

// issuerServerWith is issuerServer that waits for gate, if any, before answering, and serves no keys unless
// withKeys is set.
func issuerServerWith(t *testing.T, gate <-chan struct{}, withKeys bool) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint := sha1.Sum(key.N.Bytes())
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gate != nil {
			<-gate
		}
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": server.URL, "jwks_uri": server.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/keys":
			set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}
			if withKeys {
				set.Keys = append(set.Keys, jose.JSONWebKey{Key: &key.PublicKey, KeyID: "k", Algorithm: "RS256", Use: "sig", CertificateThumbprintSHA1: thumbprint[:]})
			}
			_ = json.NewEncoder(w).Encode(set)
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
	return &service.Discovery{ServiceEnvironments: map[string]map[string]json.RawMessage{"auth": {"prod": auth}}, Fetched: time.Now()}
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
		waitPreloadSettled(t)
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
	installAuthDiscovery(t, &d)
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

// installAuthDiscovery makes authEnv read *current and starts from an empty state.
func installAuthDiscovery(t *testing.T, current **service.Discovery) {
	t.Helper()
	oldDiscover := authEnvDiscover
	authEnvDiscover = func(context.Context) (*service.Discovery, error) { return *current, nil }
	resetAuthState()
	t.Cleanup(func() {
		waitPreloadSettled(t)
		authEnvDiscover = oldDiscover
		resetAuthState()
	})
}

// waitPreloadSettled waits until no changed environment is loading.
func waitPreloadSettled(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		authState.Lock()
		pending := authState.pending
		authState.Unlock()
		if !pending {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("preload did not finish")
}

// A preload superseded by a newer discovery is discarded instead of installed.
func TestAuthEnvDiscardsSupersededPreload(t *testing.T) {
	gate := make(chan struct{})
	first, moved := issuerServer(t), issuerServerWith(t, gate, true)
	current := discoveryWithIssuer(t, first.URL)
	installAuthDiscovery(t, &current)
	initial, err := authEnv(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	current = discoveryWithIssuer(t, moved.URL)
	_, _ = authEnv(context.Background())
	current = discoveryWithIssuer(t, first.URL)
	_, _ = authEnv(context.Background())
	close(gate)
	waitPreloadSettled(t)
	if e, _ := authEnv(context.Background()); e != initial {
		t.Fatalf("environment issuer = %v, want the restored %s", e.Issuer, first.URL)
	}
}

// An issuer that serves no signing keys does not replace the working environment.
func TestAuthEnvKeepsEnvironmentWithoutSigningKeys(t *testing.T) {
	first, keyless := issuerServer(t), issuerServerWith(t, nil, false)
	current := discoveryWithIssuer(t, first.URL)
	installAuthDiscovery(t, &current)
	initial, err := authEnv(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	current = discoveryWithIssuer(t, keyless.URL)
	_, _ = authEnv(context.Background())
	waitPreloadSettled(t)
	if e, _ := authEnv(context.Background()); e != initial {
		t.Fatalf("environment issuer = %v, want the working %s", e.Issuer, first.URL)
	}
	authState.Lock()
	backingOff := time.Now().Before(authState.retryAt)
	authState.Unlock()
	if !backingOff {
		t.Fatal("failed preload is not backing off")
	}
}

// An older Discovery read before a refresh does not roll back a change a newer one started.
func TestAuthEnvIgnoresOlderDiscovery(t *testing.T) {
	gate := make(chan struct{})
	first, moved := issuerServer(t), issuerServerWith(t, gate, true)
	older := discoveryWithIssuer(t, first.URL)
	current := older
	installAuthDiscovery(t, &current)
	t.Cleanup(func() { close(gate) })
	if _, err := authEnv(context.Background()); err != nil {
		t.Fatal(err)
	}
	current = discoveryWithIssuer(t, moved.URL)
	_, _ = authEnv(context.Background())
	stale := discoveryWithIssuer(t, first.URL)
	stale.Fetched = older.Fetched
	current = stale
	_, _ = authEnv(context.Background())
	authState.Lock()
	want := authState.want
	authState.Unlock()
	if want == nil || want.Issuer.String() != moved.URL {
		t.Fatalf("pending environment = %v, want the newer issuer %s", want, moved.URL)
	}
}

// resetAuthState empties the authorization environment authEnv maintains.
func resetAuthState() {
	authState.Lock()
	defer authState.Unlock()
	authState.env, authState.seen, authState.want, authState.pending, authState.retryAt = nil, nil, nil, false, time.Time{}
}
