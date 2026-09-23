package minecraft

import (
	"bytes"
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

func testPacket(id uint32) packet.Packet { return &packet.Unknown{PacketID: id} }

func TestConn_SendDelayHoldsFlushedPacketsUntilDue(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	const delay = 150 * time.Millisecond
	if err := conn.SetSendDelay(delay); err != nil {
		t.Fatalf("SetSendDelay: %v", err)
	}
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

func TestConn_SendDelayTimerLeavesUnflushedPacketsToTheOwner(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	if err := conn.SetSendDelay(50 * time.Millisecond); err != nil {
		t.Fatalf("SetSendDelay: %v", err)
	}
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
	if err := conn.SetSendDelay(100 * time.Millisecond); err != nil {
		t.Fatalf("SetSendDelay: %v", err)
	}
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
	if err := conn.SetSendDelay(time.Hour); err != nil {
		t.Fatalf("SetSendDelay: %v", err)
	}
	if err := conn.WritePacketImmediate(testPacket(700)); err != nil {
		t.Fatalf("WritePacketImmediate: %v", err)
	}
	expectNothingSent(t, ids, 50*time.Millisecond)

	if err := conn.SetSendDelay(0); err != nil {
		t.Fatalf("SetSendDelay(0): %v", err)
	}
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

func TestConn_EnablingCompressionSendsHeldPacketsUncompressedFirst(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	if err := conn.SetSendDelay(time.Hour); err != nil {
		t.Fatalf("SetSendDelay: %v", err)
	}
	// Flushed before compression is enabled, like NetworkSettings during login: the peer still reads
	// uncompressed batches, so the held packet must go out before the encoder changes.
	if err := conn.WritePacketImmediate(testPacket(700)); err != nil {
		t.Fatalf("WritePacketImmediate: %v", err)
	}
	if err := conn.handleNetworkSettings(&packet.NetworkSettings{CompressionAlgorithm: packet.FlateCompression.EncodeCompression()}); err != nil {
		t.Fatalf("handleNetworkSettings: %v", err)
	}
	expectSent(t, ids, 700, time.Second)
}

func TestConn_CloseSendsPacketsHeldBySendDelay(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	if err := conn.SetSendDelay(time.Hour); err != nil {
		t.Fatalf("SetSendDelay: %v", err)
	}
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
