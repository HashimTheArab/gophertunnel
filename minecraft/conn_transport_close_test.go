package minecraft

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/endpoint"
	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// contextConn is a transport that, like a NetherNet connection, reports its closure through a
// context. go-nethernet cancels it as soon as SCTP closes, while the messages delivered before that are
// still being read, and cancels it with net.ErrClosed when closed locally.
type contextConn struct {
	net.Conn
	ctx    context.Context
	cancel context.CancelCauseFunc
}

func (c contextConn) Context() context.Context { return c.ctx }

func (c contextConn) Close() error {
	c.cancel(net.ErrClosed)
	return c.Conn.Close()
}

// newTransportClosingConn returns a batch-reading Conn over a transport whose closure the test controls.
func newTransportClosingConn(t *testing.T) (*Conn, context.CancelCauseFunc) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	ctx, cancel := context.WithCancelCause(context.Background())
	conn := newConn(contextConn{Conn: client, ctx: ctx, cancel: cancel}, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
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
	for _, test := range []struct {
		name     string
		loggedIn bool
		oneBatch bool
	}{
		// Before login, received packets are deferred; once logged in they are collected into batches.
		{name: "during login"},
		{name: "logged in", loggedIn: true},
		{name: "logged in, same wire batch", loggedIn: true, oneBatch: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			conn, closeTransport := newTransportClosingConn(t)
			conn.loggedIn = test.loggedIn

			closeTransport(errors.New("nethernet: SCTP transport closed"))
			go func() {
				var buf bytes.Buffer
				_ = (&packet.Header{PacketID: packet.IDText}).Write(&buf)
				(&packet.Text{TextType: packet.TextTypeRaw, Message: "last words"}).Marshal(protocol.NewWriter(&buf, 0))
				time.Sleep(50 * time.Millisecond)
				if err := conn.receive(buf.Bytes()); err != nil {
					t.Errorf("receive text: %v", err)
				}
				if !test.oneBatch {
					conn.flushBatch()
				}
				if err := conn.receive(encodedDisconnect(t, "bye")); err != nil {
					t.Errorf("receive disconnect: %v", err)
				}
				conn.flushBatch()
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
		})
	}
}

func TestReadBatch_LocalCloseIsReportedWithoutWaiting(t *testing.T) {
	t.Parallel()
	conn, _ := newTransportClosingConn(t)
	conn.loggedIn = true

	// Closing the Conn closes its transport, which cancels the transport's context too. The read loop
	// has not ended and then decodes a Disconnect that was already received.
	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := conn.receive(encodedDisconnect(t, "too late")); err != nil {
		t.Fatalf("receive disconnect: %v", err)
	}

	start := time.Now()
	_, err := conn.ReadBatch()
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReadBatch() error = %v, want the local closure", err)
	}
	if elapsed := time.Since(start); elapsed > transportDrainTimeout/2 {
		t.Fatalf("ReadBatch() took %v, want no wait for the read loop after a local close", elapsed)
	}
}

func TestDoSpawnContext_StopsWaitingForTheReadLoopWhenItsContextEnds(t *testing.T) {
	t.Parallel()
	conn, closeTransport := newTransportClosingConn(t)
	closeTransport(errors.New("nethernet: SCTP transport closed"))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := conn.DoSpawnContext(ctx); err == nil {
		t.Fatal("DoSpawnContext() succeeded on a closed Conn")
	}
	if elapsed := time.Since(start); elapsed > transportDrainTimeout/2 {
		t.Fatalf("DoSpawnContext() took %v, want it to stop waiting when its context ends", elapsed)
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

func TestReadBatch_DisconnectThatClosedTheConnIsTheCause(t *testing.T) {
	t.Parallel()
	conn, _ := newTransportClosingConn(t)
	conn.loggedIn = true

	// The transport stays up: the Disconnect itself closes the Conn.
	if err := conn.receive(encodedDisconnect(t, "server closed")); err != nil {
		t.Fatalf("receive disconnect: %v", err)
	}
	_, err := conn.ReadBatch()
	var disconnect DisconnectError
	if !errors.As(err, &disconnect) || disconnect.Error() != "server closed" {
		t.Fatalf("ReadBatch() error = %v, want the Disconnect", err)
	}
}

// spawnedOverNetherNet returns a spawned client Conn and its server Conn, joined over NetherNet with HTTP
// signaling on loopback.
func spawnedOverNetherNet(t *testing.T) (client, server *Conn) {
	t.Helper()
	signaling := endpoint.HandlerConfig{Logger: slog.New(slog.DiscardHandler)}.New()
	t.Cleanup(func() { _ = signaling.Close() })
	network := NetherNet{Signaling: signaling, ListenConfig: nethernet.ListenConfig{AllowAnonymous: true, DisableTrickleICE: true}}
	listener, err := (ListenConfig{AuthenticationDisabled: true, ErrorLog: slog.New(slog.DiscardHandler)}).ListenNetwork(network, "test")
	if err != nil {
		t.Fatalf("ListenNetwork: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	httpServer := httptest.NewServer(signaling)
	t.Cleanup(httpServer.Close)

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	started := make(chan *Conn, 1)
	go func() {
		defer close(started)
		accepted, err := listener.Accept()
		if err != nil {
			return
		}
		if err := accepted.(*Conn).StartGameContext(ctx, GameData{}); err == nil {
			started <- accepted.(*Conn)
		}
	}()
	client, err = Dialer{ErrorLog: slog.New(slog.DiscardHandler)}.DialContextNetwork(ctx,
		AddressNetwork{NetherNet: NetherNet{Dialer: nethernet.Dialer{AllowIdentitylessServer: true}}}, httpServer.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.DoSpawnContext(ctx); err != nil {
		t.Fatalf("DoSpawn: %v", err)
	}
	server, ok := <-started
	if !ok {
		t.Fatal("the server did not start the game")
	}
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

// The dialer's and the listener's read loops both mark their end, so a reader whose peer dropped the
// transport is released as soon as the loop has drained, not after transportDrainTimeout.
func TestReadLoopsReleaseReadersWhenThePeerDrops(t *testing.T) {
	t.Parallel()
	for _, side := range []string{"dialer", "listener"} {
		t.Run(side, func(t *testing.T) {
			t.Parallel()
			client, server := spawnedOverNetherNet(t)
			reader, peer := client, server
			if side == "listener" {
				reader, peer = server, client
			}
			_ = peer.Abort()

			// Packets queued before the drop are still read first.
			start := time.Now()
			for {
				if _, err := reader.ReadPacket(); err != nil {
					break
				}
			}
			if elapsed := time.Since(start); elapsed > transportDrainTimeout/2 {
				t.Fatalf("ReadPacket() took %v, want the read loop's end to release it", elapsed)
			}
		})
	}
}
