package minecraft

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// contextConn is a transport that, like a NetherNet connection, reports its closure through a
// context. go-nethernet cancels it as soon as SCTP closes, while the messages delivered before that are
// still being read.
type contextConn struct {
	net.Conn
	ctx context.Context
}

func (c contextConn) Context() context.Context { return c.ctx }

// newTransportClosingConn returns a batch-reading Conn over a transport whose closure the test controls.
func newTransportClosingConn(t *testing.T) (*Conn, context.CancelCauseFunc) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	ctx, cancel := context.WithCancelCause(context.Background())
	conn := newConn(contextConn{Conn: client, ctx: ctx}, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	conn.pool = conn.proto.Packets(false)
	conn.batchReading = true
	return conn, cancel
}

// encodedDisconnect returns a serialised Disconnect packet carrying message.
func encodedDisconnect(t *testing.T, message string) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := (&packet.Header{PacketID: packet.IDDisconnect}).Write(&buf); err != nil {
		t.Fatalf("write header: %v", err)
	}
	(&packet.Disconnect{Reason: packet.DisconnectReasonKicked, Message: message}).Marshal(protocol.NewWriter(&buf, 0))
	return buf.Bytes()
}

func TestReadBatch_DisconnectReadAfterTransportClosedIsTheCause(t *testing.T) {
	t.Parallel()
	conn, closeTransport := newTransportClosingConn(t)
	transportErr := errors.New("nethernet: SCTP transport closed")

	// The peer sent a Disconnect and closed: the transport reports the closure before the read loop
	// has decoded the final message.
	closeTransport(transportErr)
	go func() {
		time.Sleep(50 * time.Millisecond)
		if err := conn.receive(encodedDisconnect(t, "You are banned")); err != nil {
			t.Errorf("receive disconnect: %v", err)
		}
		conn.endReadLoop()
	}()

	_, err := conn.ReadBatch()
	var disconnect DisconnectError
	if !errors.As(err, &disconnect) || disconnect.Error() != "You are banned" {
		t.Fatalf("ReadBatch() error = %v, want the Disconnect message", err)
	}
	if errors.Is(err, transportErr) {
		t.Fatalf("ReadBatch() error = %v, still carries the transport closure", err)
	}
}

func TestReadBatch_PacketsBeforeTheDisconnectAreReadFirst(t *testing.T) {
	t.Parallel()
	conn, closeTransport := newTransportClosingConn(t)

	closeTransport(errors.New("nethernet: SCTP transport closed"))
	go func() {
		var buf bytes.Buffer
		_ = (&packet.Header{PacketID: packet.IDText}).Write(&buf)
		(&packet.Text{TextType: packet.TextTypeRaw, Message: "last words"}).Marshal(protocol.NewWriter(&buf, 0))
		time.Sleep(50 * time.Millisecond)
		if err := conn.receive(buf.Bytes()); err != nil {
			t.Errorf("receive text: %v", err)
		}
		conn.flushBatch()
		if err := conn.receive(encodedDisconnect(t, "bye")); err != nil {
			t.Errorf("receive disconnect: %v", err)
		}
		conn.endReadLoop()
	}()

	packets, err := conn.ReadBatch()
	if err != nil || len(packets) != 1 {
		t.Fatalf("ReadBatch() = %v, %v; want the Text packet sent before the Disconnect", packets, err)
	}
	_, err = conn.ReadBatch()
	var disconnect DisconnectError
	if !errors.As(err, &disconnect) || disconnect.Error() != "bye" {
		t.Fatalf("second ReadBatch() error = %v, want the Disconnect", err)
	}
}

func TestReadBatch_TransportClosedWithoutDisconnectReportsTheTransport(t *testing.T) {
	t.Parallel()
	conn, closeTransport := newTransportClosingConn(t)
	transportErr := errors.New("nethernet: SCTP transport closed")

	closeTransport(transportErr)
	conn.endReadLoop()

	if _, err := conn.ReadBatch(); !errors.Is(err, transportErr) {
		t.Fatalf("ReadBatch() error = %v, want the transport closure", err)
	}
}
