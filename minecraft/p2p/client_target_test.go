package p2p

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
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

	data := login.ClientData{Nonce: "stale"}
	target.ApplyClientData(&data)
	if data.Nonce != "joined-player-nonce" {
		t.Fatalf("Nonce = %q, want joined-player-nonce", data.Nonce)
	}
}

// Signaling setup requests go through the configured HTTP client, and a failed dial returns no connection.
func TestDialClientSignalingUsesConfiguredHTTPClient(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests.Add(1)
		return &http.Response{StatusCode: http.StatusBadRequest, Header: make(http.Header), Body: http.NoBody, Request: r}, nil
	})}
	conn, err := DialClientSignaling(context.Background(), nil, ClientSignalingOptions{HTTPClient: client})
	if err == nil {
		t.Fatal("DialClientSignaling succeeded against a failing service")
	}
	if conn != nil {
		t.Fatalf("DialClientSignaling connection = %#v, want nil after dial failure", conn)
	}
	if requests.Load() == 0 {
		t.Fatal("DialClientSignaling did not use the configured HTTP client")
	}
}

// roundTripFunc is an http.RoundTripper backed by a function.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

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
