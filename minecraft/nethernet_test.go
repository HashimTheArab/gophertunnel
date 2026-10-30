package minecraft

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/df-mc/go-nethernet"
)

func TestNetherNetDialContextClosesDialedSignalingWithConn(t *testing.T) {
	t.Parallel()

	signaling := newTestNetherNetSignaling()
	transport := newTestTransportConn(t)

	network := NetherNet{
		DialSignaling: func(_ context.Context, address string) (SignalingConn, error) {
			if address != "remote-network-id" {
				t.Fatalf("signaling address = %q, want remote-network-id", address)
			}
			return signaling, nil
		},
		dial: func(_ context.Context, address string, got nethernet.Signaling, _ nethernet.Dialer) (net.Conn, error) {
			if address != "remote-network-id" {
				t.Fatalf("dial address = %q, want remote-network-id", address)
			}
			if got != signaling {
				t.Fatal("dial did not receive the signaling connection")
			}
			return transport, nil
		},
	}

	conn, err := network.DialContext(context.Background(), "remote-network-id")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	if signaling.closeCount() != 0 {
		t.Fatal("dialed signaling closed before the connection")
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	signaling.awaitClose(t)
}

func TestNetherNetDialContextRejectsContextlessTransport(t *testing.T) {
	t.Parallel()

	signaling := newTestNetherNetSignaling()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })

	network := NetherNet{
		DialSignaling: func(context.Context, string) (SignalingConn, error) {
			return signaling, nil
		},
		dial: func(context.Context, string, nethernet.Signaling, nethernet.Dialer) (net.Conn, error) {
			return client, nil
		},
	}

	if _, err := network.DialContext(context.Background(), "remote-network-id"); err == nil {
		t.Fatal("DialContext accepted a transport that cannot release signaling")
	}
	signaling.awaitClose(t)
}

func TestNetherNetDialContextPrefersDialSignaling(t *testing.T) {
	t.Parallel()

	shared := newTestNetherNetSignaling()
	dialed := newTestNetherNetSignaling()
	transport := newTestTransportConn(t)

	network := NetherNet{
		Signaling: shared,
		DialSignaling: func(context.Context, string) (SignalingConn, error) {
			return dialed, nil
		},
		dial: func(_ context.Context, _ string, got nethernet.Signaling, _ nethernet.Dialer) (net.Conn, error) {
			if got != dialed {
				t.Fatal("dial did not prefer the per-dial signaling connection")
			}
			return transport, nil
		},
	}

	conn, err := network.DialContext(context.Background(), "remote-network-id")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	dialed.awaitClose(t)
	if shared.closeCount() != 0 {
		t.Fatalf("shared signaling close count = %d, want 0", shared.closeCount())
	}
}

func TestNetherNetDialContextPropagatesDialFailure(t *testing.T) {
	t.Parallel()

	signaling := newTestNetherNetSignaling()
	dialErr := errors.New("dial failed")
	network := NetherNet{
		DialSignaling: func(context.Context, string) (SignalingConn, error) {
			return signaling, nil
		},
		dial: func(context.Context, string, nethernet.Signaling, nethernet.Dialer) (net.Conn, error) {
			return nil, dialErr
		},
		signalingCloseDelay: time.Millisecond,
	}

	_, err := network.DialContext(context.Background(), "remote-network-id")
	if !errors.Is(err, dialErr) {
		t.Fatalf("DialContext error = %v, want %v", err, dialErr)
	}
	signaling.awaitClose(t)
}

func TestNetherNetDialContextRejectsNilTransport(t *testing.T) {
	t.Parallel()

	signaling := newTestNetherNetSignaling()
	network := NetherNet{
		DialSignaling: func(context.Context, string) (SignalingConn, error) {
			return signaling, nil
		},
		dial: func(context.Context, string, nethernet.Signaling, nethernet.Dialer) (net.Conn, error) {
			return nil, nil
		},
	}

	_, err := network.DialContext(context.Background(), "remote-network-id")
	if err == nil {
		t.Fatal("DialContext accepted a nil transport connection")
	}
	signaling.awaitClose(t)
}

func TestNetherNetDialContextIdentityProviderPassesVerifiedIssuer(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate identity key: %v", err)
	}
	const (
		token  = "multiplayer-token"
		issuer = "https://authorization.example.test"
	)
	presetIdentity := &nethernet.Identity{Domain: "https://preset.example.test"}

	network := NetherNet{
		Signaling: newTestNetherNetSignaling(),
		Dialer:    nethernet.Dialer{Identity: presetIdentity},
		dial: func(_ context.Context, _ string, _ nethernet.Signaling, dialer nethernet.Dialer) (net.Conn, error) {
			if dialer.Identity == nil {
				t.Fatal("identity was not passed to the NetherNet dialer")
			}
			if dialer.Identity == presetIdentity {
				t.Fatal("verified identity did not replace the preconfigured identity")
			}
			if dialer.Identity.PrivateKey != key {
				t.Fatal("identity private key was not preserved")
			}
			if dialer.Identity.Token != token {
				t.Fatalf("identity token = %q, want %q", dialer.Identity.Token, token)
			}
			if dialer.Identity.Domain != issuer {
				t.Fatalf("identity domain = %q, want %q", dialer.Identity.Domain, issuer)
			}
			client, server := net.Pipe()
			t.Cleanup(func() { _ = server.Close() })
			return client, nil
		},
	}

	conn, err := network.DialContextIdentityProvider(context.Background(), "remote-network-id", token, key, issuer)
	if err != nil {
		t.Fatalf("DialContextIdentityProvider: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestNetherNetDialContextIdentityUsesCallerCredentials(t *testing.T) {
	t.Parallel()

	callerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate caller identity key: %v", err)
	}
	presetKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate preset identity key: %v", err)
	}
	const (
		callerToken = "caller-token"
		issuer      = "https://authorization.example.test"
	)

	network := NetherNet{
		Signaling: newTestNetherNetSignaling(),
		Dialer: nethernet.Dialer{Identity: &nethernet.Identity{
			PrivateKey: presetKey,
			Token:      "preset-token",
			Domain:     issuer,
		}},
		dial: func(_ context.Context, _ string, _ nethernet.Signaling, dialer nethernet.Dialer) (net.Conn, error) {
			if dialer.Identity.PrivateKey != callerKey {
				t.Fatal("caller identity private key was not used")
			}
			if dialer.Identity.Token != callerToken {
				t.Fatalf("identity token = %q, want %q", dialer.Identity.Token, callerToken)
			}
			if dialer.Identity.Domain != issuer {
				t.Fatalf("identity domain = %q, want %q", dialer.Identity.Domain, issuer)
			}
			client, server := net.Pipe()
			t.Cleanup(func() { _ = server.Close() })
			return client, nil
		},
	}

	conn, err := network.DialContextIdentity(context.Background(), "remote-network-id", callerToken, callerKey)
	if err != nil {
		t.Fatalf("DialContextIdentity: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestNetherNetDialContextIdentityProviderRejectsMissingIssuer(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate identity key: %v", err)
	}
	dialed := false
	network := NetherNet{
		Signaling: newTestNetherNetSignaling(),
		dial: func(context.Context, string, nethernet.Signaling, nethernet.Dialer) (net.Conn, error) {
			dialed = true
			return nil, nil
		},
	}

	_, err = network.DialContextIdentityProvider(context.Background(), "remote-network-id", "multiplayer-token", key, "")
	if err == nil {
		t.Fatal("DialContextIdentityProvider accepted an empty identity provider")
	}
	if dialed {
		t.Fatal("DialContextIdentityProvider dialed before validating the identity provider")
	}
}

// testTransportConn stands in for *nethernet.Conn: a transport whose Context ends when it closes.
type testTransportConn struct {
	net.Conn
	cancel context.CancelFunc
	ctx    context.Context
}

func newTestTransportConn(t *testing.T) *testTransportConn {
	t.Helper()

	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &testTransportConn{Conn: client, ctx: ctx, cancel: cancel}
}

func (c *testTransportConn) Context() context.Context { return c.ctx }

func (c *testTransportConn) Close() error {
	c.cancel()
	return c.Conn.Close()
}

type testNetherNetSignaling struct {
	ctx context.Context

	mu     sync.Mutex
	closed int
}

func newTestNetherNetSignaling() *testNetherNetSignaling {
	return &testNetherNetSignaling{ctx: context.Background()}
}

func (*testNetherNetSignaling) Signal(context.Context, *nethernet.Signal) error { return nil }
func (*testNetherNetSignaling) Notify(nethernet.Notifier) func()                { return func() {} }
func (s *testNetherNetSignaling) Context() context.Context                      { return s.ctx }
func (*testNetherNetSignaling) Credentials(context.Context) (*nethernet.Credentials, error) {
	return nil, nil
}
func (*testNetherNetSignaling) NetworkID() string { return "local-network-id" }
func (*testNetherNetSignaling) PongData([]byte)   {}

func (s *testNetherNetSignaling) Close() error {
	s.mu.Lock()
	s.closed++
	s.mu.Unlock()
	return nil
}

func (s *testNetherNetSignaling) closeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// awaitClose waits for the signaling to be closed, which NetherNet does asynchronously.
func (s *testNetherNetSignaling) awaitClose(t *testing.T) {
	t.Helper()

	deadline := time.Now().Add(time.Second * 5)
	for s.closeCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("dialed signaling was not closed")
		}
		time.Sleep(time.Millisecond)
	}
}

// A saved key is reused across loads, so clients that trusted it on first use are not asked again.
func TestNetherNetServerIdentityReusesSavedKey(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "keys", "nethernet.pem")
	first, err := NetherNetServerIdentity(path)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	second, err := NetherNetServerIdentity(path)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	a, err := first(context.Background())
	if err != nil {
		t.Fatalf("issue first identity: %v", err)
	}
	b, err := second(context.Background())
	if err != nil {
		t.Fatalf("issue second identity: %v", err)
	}
	if !a.PrivateKey.Equal(b.PrivateKey) {
		t.Fatal("second load generated a new key")
	}
	if a.Domain != "self" {
		t.Fatalf("domain = %q, want self", a.Domain)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := info.Mode().Perm(); runtime.GOOS != "windows" && perm != 0o600 {
		t.Fatalf("key file mode = %v, want 0600", perm)
	}
}

// An unreadable key file is reported instead of being silently replaced with a new identity.
func TestNetherNetServerIdentityRejectsInvalidKey(t *testing.T) {
	t.Parallel()

	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(p256)
	if err != nil {
		t.Fatalf("marshal P-256 key: %v", err)
	}
	full := encodeNetherNetTestKey(t)
	for name, contents := range map[string][]byte{
		"empty":     {},
		"not PEM":   []byte("not a key"),
		"P-256":     pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}),
		"RSA type":  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}),
		"truncated": full[:len(full)/2],
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "nethernet.pem")
			if err := os.WriteFile(path, contents, 0o600); err != nil {
				t.Fatalf("write key: %v", err)
			}
			if _, err := NetherNetServerIdentity(path); err == nil {
				t.Fatal("invalid key was accepted")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read key: %v", err)
			}
			if string(after) != string(contents) {
				t.Fatal("invalid key file was overwritten")
			}
		})
	}
}

// Concurrent first starts in one process all use the one key that reached disk.
func TestNetherNetServerKeyConcurrentCreatorsAgree(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "nethernet.pem")
	keys := make([]*ecdsa.PrivateKey, 16)
	var wg sync.WaitGroup
	for i := range keys {
		wg.Go(func() {
			key, err := loadOrCreateNetherNetKey(path)
			if err != nil {
				t.Errorf("creator %d: %v", i, err)
			}
			keys[i] = key
		})
	}
	wg.Wait()
	if t.Failed() {
		return
	}
	saved := readNetherNetTestKey(t, path)
	for i, key := range keys {
		if !key.Equal(saved) {
			t.Fatalf("creator %d uses a key that is not the saved one", i)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read key dir: %v", err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if len(names) != 2 || names[0] != "nethernet.pem" || names[1] != "nethernet.pem.lock" {
		t.Fatalf("key dir holds %v, want only the key and its lock", names)
	}
	for _, name := range names {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if perm := info.Mode().Perm(); runtime.GOOS != "windows" && perm != 0o600 {
			t.Fatalf("%s mode = %v, want 0600", name, perm)
		}
	}
}

// Concurrent first starts in separate processes all use the one key that reached disk.
func TestNetherNetServerKeyProcessesAgree(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nethernet.pem")
	outputs := make([][]byte, 4)
	var wg sync.WaitGroup
	for i := range outputs {
		wg.Go(func() {
			out, err := netherNetKeyHelper(t, "create", path).Output()
			if err != nil {
				t.Errorf("creator process %d: %v", i, err)
			}
			outputs[i] = out
		})
	}
	wg.Wait()
	if t.Failed() {
		return
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved key: %v", err)
	}
	for i, out := range outputs {
		if string(out) != string(saved) {
			t.Fatalf("creator process %d uses a key that is not the saved one", i)
		}
	}
}

// A creator that waited for the lock adopts the key saved meanwhile instead of replacing it.
func TestNetherNetServerKeyNeverReplacesExistingKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "nethernet.pem")
	lock, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatalf("open lock: %v", err)
	}
	defer lock.Close()
	if err := lockFile(lock); err != nil {
		t.Fatalf("lock: %v", err)
	}
	type result struct {
		key *ecdsa.PrivateKey
		err error
	}
	waited := make(chan result, 1)
	go func() {
		key, err := loadOrCreateNetherNetKey(path)
		waited <- result{key, err}
	}()
	time.Sleep(50 * time.Millisecond)
	existing := encodeNetherNetTestKey(t)
	if err := os.WriteFile(filepath.Join(dir, "saved"), existing, 0o600); err != nil {
		t.Fatalf("write existing key: %v", err)
	}
	if err := os.Rename(filepath.Join(dir, "saved"), path); err != nil {
		t.Fatalf("save existing key: %v", err)
	}
	if err := unlockFile(lock); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	r := <-waited
	if r.err != nil {
		t.Fatalf("load: %v", r.err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if string(after) != string(existing) {
		t.Fatal("existing key was replaced")
	}
	if string(encodeNetherNetTestPrivateKey(t, r.key)) != string(existing) {
		t.Fatal("creator does not use the existing key")
	}
}

// A creator killed mid-write leaves no key at path, and its lock dies with it.
func TestNetherNetServerKeyCrashLeavesNoPartialKey(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nethernet.pem")
	crashed := netherNetKeyHelper(t, "crash", path)
	stdout, err := crashed.StdoutPipe()
	if err != nil {
		t.Fatalf("pipe crashing creator: %v", err)
	}
	if err := crashed.Start(); err != nil {
		t.Fatalf("start crashing creator: %v", err)
	}
	if _, err := io.ReadFull(stdout, make([]byte, 1)); err != nil {
		_ = crashed.Process.Kill()
		t.Fatalf("crashing creator never started writing: %v", err)
	}
	if err := crashed.Process.Kill(); err != nil {
		t.Fatalf("kill creator: %v", err)
	}
	_ = crashed.Wait()
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("crashed creator left a file at the key path: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		key, err := loadOrCreateNetherNetKey(path)
		if err == nil && !key.Equal(readNetherNetTestKey(t, path)) {
			err = errors.New("returned key is not the saved one")
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("load after crash: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("load after crash is still waiting for the dead creator's lock")
	}
}

// netherNetKeyHelperEnv names the key path a helper process works on; the mode is its own variable.
const netherNetKeyHelperEnv, netherNetKeyHelperModeEnv = "GOPHERTUNNEL_NETHERNET_KEY_HELPER", "GOPHERTUNNEL_NETHERNET_KEY_HELPER_MODE"

// netherNetKeyHelper returns a command running TestNetherNetServerKeyHelperProcess in mode on path.
func netherNetKeyHelper(t *testing.T, mode, path string) *exec.Cmd {
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestNetherNetServerKeyHelperProcess$")
	cmd.Env = append(os.Environ(), netherNetKeyHelperEnv+"="+path, netherNetKeyHelperModeEnv+"="+mode)
	cmd.Stderr = os.Stderr
	return cmd
}

// TestNetherNetServerKeyHelperProcess is the child process of the multi-process key tests. In create
// mode it prints the key it loads; in crash mode it takes the lock, writes part of a key the way a
// creator does, reports it on stdout and waits to be killed.
func TestNetherNetServerKeyHelperProcess(t *testing.T) {
	path := os.Getenv(netherNetKeyHelperEnv)
	if path == "" {
		t.Skip("run only as a helper process")
	}
	switch os.Getenv(netherNetKeyHelperModeEnv) {
	case "create":
		key, err := loadOrCreateNetherNetKey(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		_, _ = os.Stdout.Write(encodeNetherNetTestPrivateKey(t, key))
		os.Exit(0)
	case "crash":
		lock, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE, 0o600)
		if err == nil {
			err = lockFile(lock)
		}
		if err == nil {
			full := encodeNetherNetTestKey(t)
			err = os.WriteFile(path+".tmp-crashed", full[:len(full)/2], 0o600)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		_, _ = os.Stdout.Write([]byte{1})
		select {}
	}
	os.Exit(2)
}

// readNetherNetTestKey parses the key saved at path.
func readNetherNetTestKey(t *testing.T, path string) *ecdsa.PrivateKey {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved key: %v", err)
	}
	key, err := parseNetherNetKey(path, b)
	if err != nil {
		t.Fatalf("parse saved key: %v", err)
	}
	return key
}

// encodeNetherNetTestKey returns a fresh P-384 key as SEC 1 PEM.
func encodeNetherNetTestKey(t *testing.T) []byte {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return encodeNetherNetTestPrivateKey(t, key)
}

// encodeNetherNetTestPrivateKey returns key as SEC 1 PEM.
func encodeNetherNetTestPrivateKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// An offline dial still presents an identity signed by the connection key, since servers match it against the login.
func TestNetherNetDialContextIdentitySelfSignsWithoutToken(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate identity key: %v", err)
	}
	network := NetherNet{
		Signaling: newTestNetherNetSignaling(),
		dial: func(_ context.Context, _ string, _ nethernet.Signaling, dialer nethernet.Dialer) (net.Conn, error) {
			if dialer.Identity == nil || dialer.Identity.PrivateKey != key {
				t.Fatal("offline dial did not present an identity for the connection key")
			}
			if dialer.Identity.Token == "" || dialer.Identity.Domain != offlineIdentityDomain {
				t.Fatalf("offline identity = %+v, want a self-signed token from %s", dialer.Identity, offlineIdentityDomain)
			}
			client, server := net.Pipe()
			t.Cleanup(func() { _ = server.Close() })
			return client, nil
		},
	}
	conn, err := network.DialContextIdentity(t.Context(), "remote-network-id", "", key)
	if err != nil {
		t.Fatalf("DialContextIdentity: %v", err)
	}
	_ = conn.Close()
}

// A preconfigured identity is kept on an offline dial instead of being replaced by a self-signed one.
func TestNetherNetDialContextIdentityKeepsPreconfiguredIdentityWithoutToken(t *testing.T) {
	t.Parallel()

	preset := &nethernet.Identity{Domain: "https://preset.example.test"}
	network := NetherNet{
		Signaling: newTestNetherNetSignaling(),
		Dialer:    nethernet.Dialer{Identity: preset},
		dial: func(_ context.Context, _ string, _ nethernet.Signaling, dialer nethernet.Dialer) (net.Conn, error) {
			if dialer.Identity != preset {
				t.Fatalf("offline dial presented %+v, want the preconfigured identity", dialer.Identity)
			}
			client, server := net.Pipe()
			t.Cleanup(func() { _ = server.Close() })
			return client, nil
		},
	}
	conn, err := network.DialContextIdentity(t.Context(), "remote-network-id", "", nil)
	if err != nil {
		t.Fatalf("DialContextIdentity: %v", err)
	}
	_ = conn.Close()
}

// Offline dials by address reach the self-signing path, so AddressNetwork must route identities too.
var _ identityDialer = AddressNetwork{}
