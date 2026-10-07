package minecraft

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// newSendDelayConn returns a manually flushed Conn and the IDs of the packets it puts on the wire, in order.
func newSendDelayConn(t *testing.T) (*Conn, <-chan uint32) {
	t.Helper()
	client, peer := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = peer.Close()
	})
	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	t.Cleanup(func() { _ = conn.Close() })

	ids := make(chan uint32, 16)
	go func() {
		defer close(ids)
		dec := packet.NewDecoder(peer)
		for {
			batch, err := dec.Decode()
			if err != nil {
				return
			}
			for _, data := range batch {
				var header packet.Header
				if err := header.Read(bytes.NewReader(data)); err != nil {
					return
				}
				ids <- header.PacketID
			}
		}
	}()
	return conn, ids
}

// expectSent waits for the next packet on the wire and checks its ID.
func expectSent(t *testing.T, ids <-chan uint32, want uint32, within time.Duration) {
	t.Helper()
	select {
	case got := <-ids:
		if got != want {
			t.Fatalf("sent packet %d, want %d", got, want)
		}
	case <-time.After(within):
		t.Fatalf("packet %d was not sent within %v", want, within)
	}
}

// expectNothingSent checks that no packet reaches the wire for d.
func expectNothingSent(t *testing.T, ids <-chan uint32, d time.Duration) {
	t.Helper()
	select {
	case got := <-ids:
		t.Fatalf("packet %d was sent before its delay passed", got)
	case <-time.After(d):
	}
}

// testPacket returns a minimal packet with an ID that is easy to check on the wire.
func testPacket(id uint32) packet.Packet { return &packet.Unknown{PacketID: id} }

func TestConn_SendDelayHoldsFlushedPacketsUntilDue(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	const delay = 150 * time.Millisecond
	conn.SetSendDelay(delay)
	start := time.Now()
	if err := conn.WritePacket(testPacket(700)); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	expectNothingSent(t, ids, delay/2)
	// Nothing flushes the Conn again, so only the delay timer can send the held packet.
	expectSent(t, ids, 700, 2*time.Second)
	if elapsed := time.Since(start); elapsed < delay {
		t.Fatalf("packet sent after %v, want at least %v", elapsed, delay)
	}
}

func TestConn_SendDelayLeavesUnflushedPacketsToTheOwner(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	conn.SetSendDelay(50 * time.Millisecond)
	if err := conn.WritePacketImmediate(testPacket(700)); err != nil {
		t.Fatalf("WritePacketImmediate: %v", err)
	}
	// Written after the last flush: only the owner decides when this batch closes.
	if err := conn.WritePacket(testPacket(701)); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	expectSent(t, ids, 700, 2*time.Second)
	expectNothingSent(t, ids, 150*time.Millisecond)

	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	expectSent(t, ids, 701, 2*time.Second)
}

func TestConn_SendDelayKeepsEveryWritePathInOrder(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	conn.SetSendDelay(100 * time.Millisecond)
	if err := conn.WritePacket(testPacket(700)); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if err := conn.WritePacketImmediate(testPacket(701)); err != nil {
		t.Fatalf("WritePacketImmediate: %v", err)
	}
	// A direct write would normally go out at once; it must not overtake the held packets.
	if err := conn.WritePacketDirect(testPacket(702)); err != nil {
		t.Fatalf("WritePacketDirect: %v", err)
	}
	if err := conn.WritePacket(testPacket(703)); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	for _, want := range []uint32{700, 701, 702, 703} {
		expectSent(t, ids, want, 2*time.Second)
	}
}

func TestConn_ClearingSendDelaySendsHeldPacketsNow(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	conn.SetSendDelay(time.Hour)
	if err := conn.WritePacketImmediate(testPacket(700)); err != nil {
		t.Fatalf("WritePacketImmediate: %v", err)
	}
	expectNothingSent(t, ids, 50*time.Millisecond)

	conn.SetSendDelay(0)
	expectSent(t, ids, 700, time.Second)
	if got := conn.SendDelay(); got != 0 {
		t.Fatalf("SendDelay after clearing = %v, want 0", got)
	}

	// With the delay cleared, writes go out as usual again.
	if err := conn.WritePacketDirect(testPacket(701)); err != nil {
		t.Fatalf("WritePacketDirect: %v", err)
	}
	expectSent(t, ids, 701, time.Second)
}

func TestConn_SendDelayKeepsTheEncodingPacketsWereSentWith(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	conn.SetSendDelay(time.Hour)
	// Sent before compression is enabled, like NetworkSettings during login: the peer still reads
	// uncompressed batches, so the held packet must stay uncompressed.
	if err := conn.WritePacketImmediate(testPacket(700)); err != nil {
		t.Fatalf("WritePacketImmediate: %v", err)
	}
	if err := conn.handleNetworkSettings(&packet.NetworkSettings{CompressionAlgorithm: packet.FlateCompression.EncodeCompression()}); err != nil {
		t.Fatalf("handleNetworkSettings: %v", err)
	}
	conn.SetSendDelay(0)
	expectSent(t, ids, 700, time.Second)
}

func TestConn_SendDelayHoldsWhatWasSentNotTheCallersBuffer(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	conn.SetSendDelay(time.Hour)
	var payload bytes.Buffer
	(&packet.Header{PacketID: 700}).Write(&payload)
	if _, err := conn.Write(payload.Bytes()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	// Flush has returned, so the caller may reuse its buffer while the packet is still held.
	payload.Reset()
	(&packet.Header{PacketID: 701}).Write(&payload)

	conn.SetSendDelay(0)
	expectSent(t, ids, 700, time.Second)
}

func TestConn_AbortDiscardsPacketsHeldBySendDelay(t *testing.T) {
	conn, _ := newSendDelayConn(t)
	conn.SetSendDelay(time.Hour)
	if err := conn.WritePacketImmediate(testPacket(700)); err != nil {
		t.Fatalf("WritePacketImmediate: %v", err)
	}
	_ = conn.Abort()

	conn.delay.mu.Lock()
	defer conn.delay.mu.Unlock()
	if held := len(conn.delay.held); held != 0 {
		t.Fatalf("an aborted Conn still holds %d batches", held)
	}
}

// framedConn is a transport that frames batches itself, like NetherNet.
type framedConn struct{ net.Conn }

func (framedConn) BatchHeader() []byte { return nil }

func TestConn_SendDelayKeepsTheTransportsBatchFraming(t *testing.T) {
	client, peer := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = peer.Close()
	})
	conn := newConn(framedConn{client}, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	t.Cleanup(func() { _ = conn.Abort() })

	sent := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := peer.Read(buf)
		sent <- buf[:n]
	}()
	if err := conn.WritePacketDirect(testPacket(700)); err != nil {
		t.Fatalf("WritePacketDirect: %v", err)
	}
	select {
	case data := <-sent:
		if len(data) == 0 || data[0] == 0xfe {
			t.Fatalf("sent %x, want the transport's own framing without the standard batch header", data)
		}
	case <-time.After(time.Second):
		t.Fatal("nothing was sent")
	}
}

// failingWriter fails every write.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, net.ErrClosed }

func TestDelayWriter_ReleaseReportsTheWriteFailure(t *testing.T) {
	d := &delayWriter{w: failingWriter{}}
	if err := d.set(time.Hour); err != nil {
		t.Fatalf("set: %v", err)
	}
	if _, err := d.writeBatch([]byte{1}, 1); err != nil {
		t.Fatalf("Write while delayed: %v", err)
	}
	// Close releases what is held this way, so the failure must reach its caller.
	if err := d.set(0); err == nil {
		t.Fatal("releasing a batch that failed to write reported no error")
	}
}

func TestConn_SetSendDelayReturnsReleaseFailure(t *testing.T) {
	conn, _ := newSendDelayConn(t)
	conn.delay.w = failingWriter{}
	if err := conn.SetSendDelay(time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := conn.WritePacketImmediate(testPacket(700)); err != nil {
		t.Fatal(err)
	}
	for _, delay := range []time.Duration{0, time.Hour, -time.Second} {
		if err := conn.SetSendDelay(delay); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("SetSendDelay(%v) = %v, want net.ErrClosed", delay, err)
		}
		if got := conn.SendDelay(); got != max(delay, 0) {
			t.Fatalf("SendDelay = %v, want %v", got, max(delay, 0))
		}
	}
	if err := conn.WritePacketDirect(testPacket(701)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after release failure = %v, want net.ErrClosed", err)
	}
}

// shortWriter simulates a transport that accepts only part of a batch without reporting an error.
type shortWriter struct{}

// Write deliberately violates io.Writer's full-write contract to test completion handling.
func (shortWriter) Write(data []byte) (int, error) { return len(data) - 1, nil }

func TestDelayWriter_ShortWritesNeverComplete(t *testing.T) {
	for _, delay := range []time.Duration{0, time.Hour} {
		t.Run(delay.String(), func(t *testing.T) {
			d := &delayWriter{w: shortWriter{}}
			defer d.drop()
			if err := d.set(delay); err != nil {
				t.Fatal(err)
			}
			d.setObservers([]packetCompletion{{after: 1, sent: func() { t.Error("short write completed") }}})
			_, err := d.writeBatch([]byte{1, 2}, 1)
			if delay > 0 {
				if err != nil {
					t.Fatalf("queue delayed write: %v", err)
				}
				err = d.set(0)
			}
			if !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("write error = %v, want io.ErrShortWrite", err)
			}
		})
	}
}

func TestDelayWriter_DropRejectsWritesAfterDelayChanges(t *testing.T) {
	for _, delay := range []time.Duration{0, time.Hour} {
		t.Run(delay.String(), func(t *testing.T) {
			var transport bytes.Buffer
			d := &delayWriter{w: &transport}
			defer d.drop()
			observe := func() { t.Error("dropped writer reported delivery") }
			d.setObservers([]packetCompletion{{after: 1, sent: observe}})
			d.drop()
			_ = d.set(delay)
			d.setObservers([]packetCompletion{{after: 1, sent: observe}})
			if n, err := d.writeBatch([]byte{1}, 1); n != 0 || !errors.Is(err, net.ErrClosed) {
				t.Errorf("Write after drop = (%d, %v), want (0, net.ErrClosed)", n, err)
			}
			if transport.Len() != 0 || len(d.held) != 0 || len(d.nextObservers) != 0 {
				t.Fatal("dropped writer sent or retained a batch or delivery observer")
			}
		})
	}
}

func TestConn_CloseSendsPacketsHeldBySendDelay(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	conn.SetSendDelay(time.Hour)
	if err := conn.WritePacketImmediate(testPacket(700)); err != nil {
		t.Fatalf("WritePacketImmediate: %v", err)
	}
	if err := conn.WritePacket(testPacket(701)); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	closed := make(chan error, 1)
	go func() { closed <- conn.Close() }()
	expectSent(t, ids, 700, time.Second)
	expectSent(t, ids, 701, time.Second)
	if err := <-closed; err != nil {
		t.Fatalf("Close: %v", err)
	}
}
