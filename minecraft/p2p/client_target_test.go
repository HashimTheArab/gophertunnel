package p2p

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/df-mc/go-nethernet"
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/service"
)

func TestSessionClientTargetPreservesJSONRPCDestinationAndNonce(t *testing.T) {
	t.Parallel()

	playerMessagingID := uuid.New()
	session := &Session{
		connection: Connection{
			Type:              ConnectionTypeSignalingOverJSONRPC,
			NetherNetID:       "123456789",
			PlayerMessagingID: playerMessagingID,
		},
		nonce: "joined-player-nonce",
	}

	target, err := session.ClientTarget()
	if err != nil {
		t.Fatalf("ClientTarget: %v", err)
	}
	if got := target.DialAddress(); got != playerMessagingID.String() {
		t.Fatalf("DialAddress = %q, want Player Messaging ID %q", got, playerMessagingID)
	}
	if got := target.ConnectionType(); got != ConnectionTypeSignalingOverJSONRPC {
		t.Fatalf("ConnectionType = %d, want %d", got, ConnectionTypeSignalingOverJSONRPC)
	}

	data := login.ClientData{Nonce: "stale"}
	target.ApplyClientData(&data)
	if data.Nonce != "joined-player-nonce" {
		t.Fatalf("Nonce = %q, want joined-player-nonce", data.Nonce)
	}
}

func TestDialClientSignalingJSONRPCOwnsLocalNetworkIdentity(t *testing.T) {
	t.Parallel()

	called := false
	want := newTestSignalingConn()
	conn, err := DialClientSignaling(context.Background(), ConnectionTypeSignalingOverJSONRPC, nil, ClientSignalingOptions{
		JSONRPCDial: func(context.Context, service.TokenSource, ClientSignalingOptions) (SignalingConn, error) {
			called = true
			return want, nil
		},
	})
	if err != nil {
		t.Fatalf("DialClientSignaling: %v", err)
	}
	if !called {
		t.Fatal("JSON-RPC client signaling dialer was not used")
	}
	if conn != want {
		t.Fatal("DialClientSignaling returned a different signaling connection")
	}
}

func TestDialClientSignalingSelectsWebSocket(t *testing.T) {
	t.Parallel()

	called := false
	want := newTestSignalingConn()
	conn, err := DialClientSignaling(context.Background(), ConnectionTypeSignalingOverWebSocket, nil, ClientSignalingOptions{
		WebSocketDial: func(context.Context, service.TokenSource, ClientSignalingOptions) (SignalingConn, error) {
			called = true
			return want, nil
		},
	})
	if err != nil {
		t.Fatalf("DialClientSignaling: %v", err)
	}
	if !called {
		t.Fatal("WebSocket client signaling dialer was not used")
	}
	if conn != want {
		t.Fatal("DialClientSignaling returned a different signaling connection")
	}
}

type testSignalingConn struct {
	local net.Conn
	peer  net.Conn
}

// newTestSignalingConn returns an in-memory signaling connection for dial-selection tests.
func newTestSignalingConn() *testSignalingConn {
	local, peer := net.Pipe()
	return &testSignalingConn{local: local, peer: peer}
}

func (c *testSignalingConn) Signal(context.Context, *nethernet.Signal) error { return nil }

func (c *testSignalingConn) Notify(n nethernet.Notifier) func() { return func() {} }

func (c *testSignalingConn) Context() context.Context { return context.Background() }

func (c *testSignalingConn) PongData([]byte) {}

func (c *testSignalingConn) Accept() (net.Conn, error) { return nil, net.ErrClosed }

func (c *testSignalingConn) Credentials(context.Context) (*nethernet.Credentials, error) {
	return nil, io.EOF
}

func (c *testSignalingConn) NetworkID() string { return "local-client-network-id" }

func (c *testSignalingConn) Close() error {
	_ = c.peer.Close()
	return c.local.Close()
}
