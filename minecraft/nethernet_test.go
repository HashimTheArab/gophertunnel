package minecraft

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"net"
	"os"
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

// Concurrent first starts all use the one key that reached disk, through every publish fallback.
func TestNetherNetKeyFileConcurrentCreatorsAgree(t *testing.T) {
	t.Parallel()

	for name, store := range netherNetKeyFileFallbacks(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "nethernet.pem")
			keys := make([]*ecdsa.PrivateKey, 8)
			var wg sync.WaitGroup
			for i := range keys {
				wg.Go(func() {
					key, err := store.loadOrCreate(path)
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
			if len(entries) != 1 {
				t.Fatalf("key dir holds %d entries, want only the key", len(entries))
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat key: %v", err)
			}
			if perm := info.Mode().Perm(); runtime.GOOS != "windows" && perm != 0o600 {
				t.Fatalf("key file mode = %v, want 0600", perm)
			}
		})
	}
}

// A creator that loses the race to an existing file reports it rather than replacing the key.
func TestNetherNetKeyFilePublishNeverReplaces(t *testing.T) {
	t.Parallel()

	for name, store := range netherNetKeyFileFallbacks(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path, tmp := filepath.Join(dir, "nethernet.pem"), filepath.Join(dir, "tmp")
			existing := encodeNetherNetTestKey(t)
			if err := os.WriteFile(path, existing, 0o600); err != nil {
				t.Fatalf("write existing key: %v", err)
			}
			if err := os.WriteFile(tmp, encodeNetherNetTestKey(t), 0o600); err != nil {
				t.Fatalf("write new key: %v", err)
			}
			if err := store.publish(tmp, path); !errors.Is(err, fs.ErrExist) {
				t.Fatalf("publish over existing key: err = %v, want fs.ErrExist", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read key: %v", err)
			}
			if string(after) != string(existing) {
				t.Fatal("existing key was replaced")
			}
		})
	}
}

// A locked empty claim belongs to a live creator, so its published key is used instead of a new one.
func TestNetherNetKeyFileWaitsForLiveClaim(t *testing.T) {
	t.Parallel()
	requireTryLock(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "nethernet.pem")
	claim := lockedNetherNetTestClaim(t, path)
	published := encodeNetherNetTestKey(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer claim.Close()
		time.Sleep(50 * time.Millisecond)
		tmp := filepath.Join(dir, "tmp")
		if err := os.WriteFile(tmp, published, 0o600); err != nil {
			t.Errorf("write published key: %v", err)
			return
		}
		if err := os.Rename(tmp, path); err != nil {
			t.Errorf("publish over claim: %v", err)
		}
	}()
	store := netherNetKeys
	store.claimTimeout = 10 * time.Second
	key, err := store.loadOrCreate(path)
	<-done
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if want := readNetherNetTestKey(t, path); !key.Equal(want) || string(encodeNetherNetTestPrivateKey(t, key)) != string(published) {
		t.Fatal("live claim was not waited for")
	}
}

// A live creator's claim is never removed, even when it outlasts the wait.
func TestNetherNetKeyFileKeepsLiveClaim(t *testing.T) {
	t.Parallel()
	requireTryLock(t)

	path := filepath.Join(t.TempDir(), "nethernet.pem")
	claim := lockedNetherNetTestClaim(t, path)
	defer claim.Close()
	store := netherNetKeys
	store.claimTimeout = 50 * time.Millisecond
	if _, err := store.loadOrCreate(path); err == nil {
		t.Fatal("load succeeded while a live creator held its claim")
	}
	held, err := claim.Stat()
	if err != nil {
		t.Fatalf("stat claim: %v", err)
	}
	if cur, err := os.Stat(path); err != nil || !os.SameFile(held, cur) {
		t.Fatalf("live claim was removed or replaced: %v", err)
	}
}

// An unlocked empty claim was left by a creator that died, so it is replaced by a fresh key.
func TestNetherNetKeyFileReplacesDeadClaim(t *testing.T) {
	t.Parallel()
	requireTryLock(t)

	path := filepath.Join(t.TempDir(), "nethernet.pem")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write claim: %v", err)
	}
	key, err := netherNetKeys.loadOrCreate(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !key.Equal(readNetherNetTestKey(t, path)) {
		t.Fatal("returned key is not the saved one")
	}
}

// A claim left by a publish that failed after claiming is unlocked, so the next load replaces it.
func TestNetherNetKeyFileRecoversFailedPublish(t *testing.T) {
	t.Parallel()
	requireTryLock(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "nethernet.pem")
	store := netherNetKeyFileFallbacks(t)["claim"]
	if err := store.publish(filepath.Join(dir, "missing"), path); err == nil || errors.Is(err, fs.ErrExist) {
		t.Fatalf("publish of a missing file: err = %v, want a rename failure", err)
	}
	if info, err := os.Stat(path); err != nil || info.Size() != 0 {
		t.Fatalf("failed publish did not leave its empty claim: %v", err)
	}
	key, err := store.loadOrCreate(path)
	if err != nil {
		t.Fatalf("load after failed publish: %v", err)
	}
	if !key.Equal(readNetherNetTestKey(t, path)) {
		t.Fatal("returned key is not the saved one")
	}
}

// A creator paused between claiming and locking adopts the key published after its claim was cleared,
// rather than renaming its own key over it.
func TestNetherNetKeyFilePausedCreatorKeepsReplacement(t *testing.T) {
	t.Parallel()
	requireTryLock(t)

	path := filepath.Join(t.TempDir(), "nethernet.pem")
	claimOnly := netherNetKeyFileFallbacks(t)["claim"]
	resume := make(chan struct{})
	paused := claimOnly
	paused.tryLock = func(f *os.File) (bool, error) {
		<-resume
		return netherNetKeys.tryLock(f)
	}
	type result struct {
		key *ecdsa.PrivateKey
		err error
	}
	pausedResult := make(chan result, 1)
	go func() {
		key, err := paused.loadOrCreate(path)
		pausedResult <- result{key, err}
	}()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		if _, err := os.Stat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			close(resume)
			t.Fatal("paused creator never claimed the key file")
		}
	}
	replacement, err := claimOnly.loadOrCreate(path)
	close(resume)
	if err != nil {
		t.Fatalf("replace dead-looking claim: %v", err)
	}
	r := <-pausedResult
	if r.err != nil {
		t.Fatalf("paused creator: %v", r.err)
	}
	saved := readNetherNetTestKey(t, path)
	if !replacement.Equal(saved) {
		t.Fatal("paused creator overwrote the replacement key")
	}
	if !r.key.Equal(saved) {
		t.Fatal("paused creator uses a key that is not the saved one")
	}
}

// Without file locks an empty file cannot be told from a live claim, so it is reported and kept.
func TestNetherNetKeyFileWithoutLocksKeepsEmptyFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nethernet.pem")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write empty file: %v", err)
	}
	store := netherNetKeys
	store.tryLock = nil
	if _, err := store.loadOrCreate(path); err == nil {
		t.Fatal("empty key file was accepted")
	}
	if info, err := os.Stat(path); err != nil || info.Size() != 0 {
		t.Fatalf("empty key file was replaced: %v", err)
	}
}

// Locks exclude every other open of the file, in this process too, and are released on close.
func TestTryLock(t *testing.T) {
	t.Parallel()
	requireTryLock(t)

	path := filepath.Join(t.TempDir(), "lock")
	first := lockedNetherNetTestClaim(t, path)
	second, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open second: %v", err)
	}
	defer second.Close()
	if locked, err := netherNetKeys.tryLock(second); err != nil || locked {
		t.Fatalf("second lock while first held = %v, %v; want false, nil", locked, err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first: %v", err)
	}
	if locked, err := netherNetKeys.tryLock(second); err != nil || !locked {
		t.Fatalf("second lock after first closed = %v, %v; want true, nil", locked, err)
	}
}

// The platform no-replace rename moves into a free name and refuses an occupied one.
func TestRenameNoReplace(t *testing.T) {
	t.Parallel()

	if err := probeRenameNoReplace(t); err != nil {
		t.Skipf("no-replace rename unavailable: %v", err)
	}
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "src"), filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("new"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if err := os.WriteFile(dst, []byte("old"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := renameNoReplace(src, dst); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("rename onto existing file: err = %v, want fs.ErrExist", err)
	}
	if b, err := os.ReadFile(dst); err != nil || string(b) != "old" {
		t.Fatalf("target after refused rename = %q, %v; want old", b, err)
	}
	if err := os.Remove(dst); err != nil {
		t.Fatalf("remove target: %v", err)
	}
	if err := renameNoReplace(src, dst); err != nil {
		t.Fatalf("rename onto free name: %v", err)
	}
	if b, err := os.ReadFile(dst); err != nil || string(b) != "new" {
		t.Fatalf("target after rename = %q, %v; want new", b, err)
	}
}

// netherNetKeyFileFallbacks returns key stores that each publish through one step of the fallback chain.
func netherNetKeyFileFallbacks(t *testing.T) map[string]netherNetKeyFile {
	noLink := func(string, string) error { return fs.ErrPermission } // as Android's SELinux policy answers apps
	noRename := func(string, string) error { return errors.ErrUnsupported }
	stores := map[string]netherNetKeyFile{
		"link": {link: os.Link, renameNoReplace: noRename, tryLock: netherNetKeys.tryLock, claimTimeout: 10 * time.Second},
	}
	if netherNetKeys.tryLock != nil {
		stores["claim"] = netherNetKeyFile{link: noLink, renameNoReplace: noRename, tryLock: netherNetKeys.tryLock, claimTimeout: 10 * time.Second}
	}
	if err := probeRenameNoReplace(t); err == nil {
		stores["rename"] = netherNetKeyFile{link: noLink, renameNoReplace: renameNoReplace, tryLock: netherNetKeys.tryLock, claimTimeout: 10 * time.Second}
	} else {
		t.Logf("no-replace rename unavailable, skipping that fallback: %v", err)
	}
	return stores
}

// probeRenameNoReplace reports whether the platform no-replace rename works in a test directory.
func probeRenameNoReplace(t *testing.T) error {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, nil, 0o600); err != nil {
		t.Fatalf("write probe: %v", err)
	}
	return renameNoReplace(src, filepath.Join(dir, "dst"))
}

// requireTryLock skips tests of claims on platforms without file locks, where publishing never claims.
func requireTryLock(t *testing.T) {
	if netherNetKeys.tryLock == nil {
		t.Skip("file locks unavailable")
	}
}

// lockedNetherNetTestClaim creates an empty file at path and returns it locked, as a live creator holds it.
func lockedNetherNetTestClaim(t *testing.T, path string) *os.File {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("create claim: %v", err)
	}
	if locked, err := netherNetKeys.tryLock(f); err != nil || !locked {
		_ = f.Close()
		t.Fatalf("lock claim = %v, %v", locked, err)
	}
	return f
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
