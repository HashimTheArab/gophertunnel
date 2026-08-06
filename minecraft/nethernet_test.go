package minecraft

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/df-mc/go-nethernet"
)

func TestNetherNetDialContextTransfersDialedSignalingOwnership(t *testing.T) {
	t.Parallel()

	signaling := newTestNetherNetSignaling()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })

	network := NetherNet{
		DialSignaling: func(_ context.Context, address string) (SignalingConn, error) {
			if address != "remote-network-id" {
				t.Fatalf("signaling address = %q, want remote-network-id", address)
			}
			return signaling, nil
		},
		dial: func(_ context.Context, address string, got nethernet.Signaling, dialer nethernet.Dialer) (net.Conn, error) {
			if address != "remote-network-id" {
				t.Fatalf("dial address = %q, want remote-network-id", address)
			}
			if got != signaling {
				t.Fatal("dial did not receive the signaling connection")
			}
			if !dialer.OwnSignaling {
				t.Fatal("dialer did not take ownership of the per-dial signaling connection")
			}
			return client, nil
		},
	}

	conn, err := network.DialContext(context.Background(), "remote-network-id")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestNetherNetDialContextPrefersDialSignaling(t *testing.T) {
	t.Parallel()

	shared := newTestNetherNetSignaling()
	dialed := newTestNetherNetSignaling()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })

	network := NetherNet{
		Signaling: shared,
		DialSignaling: func(context.Context, string) (SignalingConn, error) {
			return dialed, nil
		},
		dial: func(_ context.Context, _ string, got nethernet.Signaling, dialer nethernet.Dialer) (net.Conn, error) {
			if got != dialed {
				t.Fatal("dial did not prefer the per-dial signaling connection")
			}
			if !dialer.OwnSignaling {
				t.Fatal("dialer did not take ownership of the per-dial signaling connection")
			}
			return client, nil
		},
	}

	conn, err := network.DialContext(context.Background(), "remote-network-id")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
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
	}

	_, err := network.DialContext(context.Background(), "remote-network-id")
	if !errors.Is(err, dialErr) {
		t.Fatalf("DialContext error = %v, want %v", err, dialErr)
	}
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
