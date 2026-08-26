package p2p

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/df-mc/go-nethernet"
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/service"
)

func TestClientTargetFromSessionPreservesJSONRPCDestinationAndNonce(t *testing.T) {
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

	target, err := ClientTargetFromSession(session)
	if err != nil {
		t.Fatalf("ClientTargetFromSession: %v", err)
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

func TestDialClientSignalingReturnsNilConnectionOnBuiltInDialFailure(t *testing.T) {
	t.Parallel()

	for _, connectionType := range []int{
		ConnectionTypeSignalingOverJSONRPC,
		ConnectionTypeSignalingOverWebSocket,
	} {
		connectionType := connectionType
		t.Run(fmt.Sprintf("connection_type_%d", connectionType), func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			conn, err := DialClientSignaling(ctx, connectionType, nil, ClientSignalingOptions{})
			if err == nil {
				t.Fatal("DialClientSignaling returned nil error for canceled context")
			}
			if conn != nil {
				t.Fatalf("DialClientSignaling connection = %#v, want nil after dial failure", conn)
			}
		})
	}
}

func TestClientTargetCloseIsIdempotentAcrossCopies(t *testing.T) {
	t.Parallel()

	session := &testClientSession{
		connection: Connection{
			Type:              ConnectionTypeSignalingOverJSONRPC,
			NetherNetID:       "123456789",
			PlayerMessagingID: uuid.New(),
		},
		nonce: "joined-player-nonce",
	}
	target, err := ClientTargetFromSession(session)
	if err != nil {
		t.Fatalf("ClientTargetFromSession: %v", err)
	}
	targetCopy := target
	if err := target.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := targetCopy.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if session.closeCount != 1 {
		t.Fatalf("session Close calls = %d, want 1", session.closeCount)
	}
}

func TestClientTargetCloseRetriesFailedSessionLeave(t *testing.T) {
	t.Parallel()

	transientErr := errors.New("temporary MPSD failure")
	session := &testClientSession{
		connection: Connection{
			Type:              ConnectionTypeSignalingOverJSONRPC,
			NetherNetID:       "123456789",
			PlayerMessagingID: uuid.New(),
		},
		nonce:       "joined-player-nonce",
		closeErrors: []error{transientErr, nil},
	}
	target, err := ClientTargetFromSession(session)
	if err != nil {
		t.Fatalf("ClientTargetFromSession: %v", err)
	}
	targetCopy := target
	if err := target.Close(); !errors.Is(err, transientErr) {
		t.Fatalf("first Close error = %v, want %v", err, transientErr)
	}
	if err := targetCopy.Close(); err != nil {
		t.Fatalf("retry Close: %v", err)
	}
	if err := target.Close(); err != nil {
		t.Fatalf("Close after successful retry: %v", err)
	}
	if session.closeCount != 2 {
		t.Fatalf("session Close calls = %d, want 2", session.closeCount)
	}
}

type testClientSession struct {
	connection  Connection
	nonce       string
	closeCount  int
	closeErrors []error
}

func (s *testClientSession) Connection() Connection { return s.connection }

func (s *testClientSession) Nonce() string { return s.nonce }

func (s *testClientSession) Close() error {
	s.closeCount++
	if len(s.closeErrors) != 0 {
		err := s.closeErrors[0]
		s.closeErrors = s.closeErrors[1:]
		return err
	}
	return nil
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
