package minecraft

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/endpoint"
)

type memoryTrustStore struct {
	mu   sync.Mutex
	keys []string
}

func (s *memoryTrustStore) LoadTrustedKeys() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.keys), nil
}

func (s *memoryTrustStore) SaveTrustedKeys(keys []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = slices.Clone(keys)
	return nil
}

type confirmRecorder struct {
	answer bool
	asked  []string
}

func (r *confirmRecorder) confirm(_ context.Context, url string) (bool, error) {
	r.asked = append(r.asked, url)
	return r.answer, nil
}

func newServerKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &key.PublicKey
}

// An http server is asked about once: trusting it stores the key, so the next join is silent.
func TestFirstUseTrustAsksOnceForAnHTTPServer(t *testing.T) {
	store, confirm := new(memoryTrustStore), &confirmRecorder{answer: true}
	trust := &FirstUseTrust{Store: store, Confirm: confirm.confirm}
	key := newServerKey(t)
	for range 2 {
		if trusted, err := trust.TrustServer(t.Context(), "http://127.0.0.1:19132", key); err != nil || !trusted {
			t.Fatalf("TrustServer = %v, %v; want trusted", trusted, err)
		}
	}
	if !slices.Equal(confirm.asked, []string{"http://127.0.0.1:19132"}) {
		t.Fatalf("asked %q, want one prompt for the URL", confirm.asked)
	}
	if len(store.keys) != 1 {
		t.Fatalf("stored %d keys, want 1", len(store.keys))
	}
}

func TestFirstUseTrustDeclineStoresNothing(t *testing.T) {
	store, confirm := new(memoryTrustStore), &confirmRecorder{answer: false}
	trust := &FirstUseTrust{Store: store, Confirm: confirm.confirm}
	key := newServerKey(t)
	for range 2 {
		if trusted, err := trust.TrustServer(t.Context(), "http://example.com:19132", key); err != nil || trusted {
			t.Fatalf("TrustServer = %v, %v; want declined", trusted, err)
		}
	}
	if len(confirm.asked) != 2 || len(store.keys) != 0 {
		t.Fatalf("asked %d times and stored %d keys, want 2 prompts and no key", len(confirm.asked), len(store.keys))
	}
}

func TestFirstUseTrustTrustsHTTPSSilently(t *testing.T) {
	store, confirm := new(memoryTrustStore), &confirmRecorder{}
	trust := &FirstUseTrust{Store: store, Confirm: confirm.confirm}
	if trusted, err := trust.TrustServer(t.Context(), "https://example.com:19132", newServerKey(t)); err != nil || !trusted {
		t.Fatalf("TrustServer = %v, %v; want trusted", trusted, err)
	}
	if len(confirm.asked) != 0 || len(store.keys) != 1 {
		t.Fatalf("asked %d times and stored %d keys, want no prompt and the key stored", len(confirm.asked), len(store.keys))
	}
}

// Keys are not bound to a URL, so a known server presenting a new key is asked about again.
func TestFirstUseTrustAsksAgainWhenAServerKeyChanges(t *testing.T) {
	store, confirm := new(memoryTrustStore), &confirmRecorder{answer: true}
	trust := &FirstUseTrust{Store: store, Confirm: confirm.confirm}
	for range 2 {
		if _, err := trust.TrustServer(t.Context(), "http://127.0.0.1:19132", newServerKey(t)); err != nil {
			t.Fatal(err)
		}
	}
	if len(confirm.asked) != 2 || len(store.keys) != 2 {
		t.Fatalf("asked %d times and stored %d keys, want a prompt per key", len(confirm.asked), len(store.keys))
	}
}

type failingLoadStore struct {
	memoryTrustStore
	fail bool
}

func (s *failingLoadStore) LoadTrustedKeys() ([]string, error) {
	if s.fail {
		return nil, errors.New("unreadable")
	}
	return s.memoryTrustStore.LoadTrustedKeys()
}

// A store that cannot be read is never overwritten, though the join is still trusted.
func TestFirstUseTrustKeepsKeysItCouldNotLoad(t *testing.T) {
	store := &failingLoadStore{memoryTrustStore: memoryTrustStore{keys: []string{"kept"}}, fail: true}
	trust := &FirstUseTrust{Store: store, Log: slog.New(slog.DiscardHandler)}
	if trusted, err := trust.TrustServer(t.Context(), "https://example.com", newServerKey(t)); err != nil || !trusted {
		t.Fatalf("TrustServer = %v, %v; want trusted", trusted, err)
	}
	if !slices.Equal(store.keys, []string{"kept"}) {
		t.Fatalf("stored keys = %q, want the unreadable keys left alone", store.keys)
	}
}

// The store keeps the 100 most recently used keys, and reusing a key makes it the newest.
func TestFirstUseTrustKeepsTheMostRecentlyUsedKeys(t *testing.T) {
	store := new(memoryTrustStore)
	trust := &FirstUseTrust{Store: store}
	first := newServerKey(t)
	if _, err := trust.TrustServer(t.Context(), "https://first", first); err != nil {
		t.Fatal(err)
	}
	second := newServerKey(t)
	if _, err := trust.TrustServer(t.Context(), "https://second", second); err != nil {
		t.Fatal(err)
	}
	if _, err := trust.TrustServer(t.Context(), "https://first", first); err != nil {
		t.Fatal(err)
	}
	for i := range maxTrustedKeys - 1 {
		if _, err := trust.TrustServer(t.Context(), fmt.Sprintf("https://%d", i), newServerKey(t)); err != nil {
			t.Fatal(err)
		}
	}
	firstEncoded, _ := EncodeTrustedKey(first)
	secondEncoded, _ := EncodeTrustedKey(second)
	if len(store.keys) != maxTrustedKeys || !slices.Contains(store.keys, firstEncoded) || slices.Contains(store.keys, secondEncoded) {
		t.Fatalf("stored %d keys (first kept %v, second kept %v), want %d with the least recently used dropped",
			len(store.keys), slices.Contains(store.keys, firstEncoded), slices.Contains(store.keys, secondEncoded), maxTrustedKeys)
	}
}

// trustListener serves a NetherNet listener behind HTTP signaling; strip removes the answer's identity.
func trustListener(t *testing.T, strip bool) string {
	t.Helper()
	signaling := endpoint.HandlerConfig{Logger: slog.New(slog.DiscardHandler)}.New()
	t.Cleanup(func() { _ = signaling.Close() })
	listener, err := (nethernet.ListenConfig{AllowAnonymous: true, DisableTrickleICE: true, Log: slog.New(slog.DiscardHandler)}).Listen(signaling)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	var handler http.Handler = signaling
	if strip {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			recorder := httptest.NewRecorder()
			signaling.ServeHTTP(recorder, r)
			var kept []string
			for _, line := range strings.Split(recorder.Body.String(), "\r\n") {
				if !strings.HasPrefix(line, "a=identity:") {
					kept = append(kept, line)
				}
			}
			w.WriteHeader(recorder.Code)
			_, _ = io.WriteString(w, strings.Join(kept, "\r\n"))
		})
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server.Listener.Addr().String()
}

func dialWithTrust(t *testing.T, address string, trust ServerTrust) (net.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	return (AddressNetwork{ServerTrust: trust, NetherNet: NetherNet{Log: slog.New(slog.DiscardHandler)}}).DialContext(ctx, address)
}

// The prompt names the probed URL, Trust joins, and the trusted key makes the next join silent.
func TestAddressNetworkAsksServerTrustWithTheProbedURL(t *testing.T) {
	address := trustListener(t, false)
	confirm := &confirmRecorder{answer: true}
	trust := &FirstUseTrust{Store: new(memoryTrustStore), Confirm: confirm.confirm}
	for range 2 {
		conn, err := dialWithTrust(t, address, trust)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		_ = conn.Close()
	}
	if !slices.Equal(confirm.asked, []string{"http://" + address}) {
		t.Fatalf("asked %q, want one prompt for http://%s", confirm.asked, address)
	}
}

func TestAddressNetworkDeclinedServerTrustFailsTheDial(t *testing.T) {
	address := trustListener(t, false)
	conn, err := dialWithTrust(t, address, &FirstUseTrust{Confirm: (&confirmRecorder{}).confirm})
	if conn != nil {
		_ = conn.Close()
	}
	if !errors.Is(err, ErrServerNotTrusted) {
		t.Fatalf("dial error = %v, want ErrServerNotTrusted", err)
	}
}

// With ServerTrust set, a server that presents no identity is refused without asking.
func TestAddressNetworkServerTrustRefusesIdentitylessServers(t *testing.T) {
	address := trustListener(t, true)
	confirm := &confirmRecorder{answer: true}
	conn, err := dialWithTrust(t, address, &FirstUseTrust{Confirm: confirm.confirm})
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil || len(confirm.asked) != 0 {
		t.Fatalf("dial error = %v after %d prompts, want a refusal without asking", err, len(confirm.asked))
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	open := AddressNetwork{NetherNet: NetherNet{Dialer: nethernet.Dialer{AllowIdentitylessServer: true}, Log: slog.New(slog.DiscardHandler)}}
	conn, err = open.DialContext(ctx, address)
	if err != nil {
		t.Fatalf("identityless server refused without ServerTrust too: %v", err)
	}
	_ = conn.Close()
}

func TestServerTokenKeyAcceptsBothCPKForms(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := nethernet.GenerateServerIdentity(private, "self")
	if err != nil {
		t.Fatal(err)
	}
	key, err := serverTokenKey(identity.Token)
	if err != nil {
		t.Fatalf("serverTokenKey: %v", err)
	}
	if !key.Equal(&private.PublicKey) {
		t.Fatal("serverTokenKey returned another key")
	}
	if _, err := parseClaimedKey(bytes.TrimSpace([]byte(`"not base64"`))); err == nil {
		t.Fatal("parseClaimedKey accepted a malformed cpk")
	}
}
