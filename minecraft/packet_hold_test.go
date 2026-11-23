package minecraft

import (
	"errors"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// holdIDs returns a PacketHold selecting the test packets with the given IDs.
func holdIDs(ids ...uint32) PacketHold {
	return func(pk packet.Packet) bool {
		unknown, ok := pk.(*packet.Unknown)
		return ok && slices.Contains(ids, unknown.PacketID)
	}
}

// writeAll writes each test packet ID in order without flushing.
func writeAll(t *testing.T, conn *Conn, ids ...uint32) {
	t.Helper()
	for _, id := range ids {
		if err := conn.WritePacket(testPacket(id)); err != nil {
			t.Fatalf("WritePacket(%d): %v", id, err)
		}
	}
}

func TestConn_PacketHoldSendsOthersAndReleasesHeldInOrder(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	if err := conn.SetPacketHold(holdIDs(700, 702), 10); err != nil {
		t.Fatalf("SetPacketHold: %v", err)
	}
	writeAll(t, conn, 700, 701, 702, 703)
	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	expectSent(t, ids, 701, 2*time.Second)
	expectSent(t, ids, 703, 2*time.Second)

	if err := conn.SetPacketHold(nil, 0); err != nil {
		t.Fatalf("SetPacketHold(nil): %v", err)
	}
	expectSent(t, ids, 700, 2*time.Second)
	expectSent(t, ids, 702, 2*time.Second)

	// Nothing is held any more, so the next packets keep their order.
	writeAll(t, conn, 700, 704)
	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	expectSent(t, ids, 700, 2*time.Second)
	expectSent(t, ids, 704, 2*time.Second)
}

func TestConn_PacketHoldLimitReleasesAndKeepsHolding(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	if err := conn.SetPacketHold(holdIDs(700), 2); err != nil {
		t.Fatalf("SetPacketHold: %v", err)
	}
	// The second held packet reaches the limit and queues both behind 701; the third is held again.
	writeAll(t, conn, 700, 701, 700, 700, 702)
	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	for _, want := range []uint32{701, 700, 700, 702} {
		expectSent(t, ids, want, 2*time.Second)
	}
	if err := conn.SetPacketHold(nil, 0); err != nil {
		t.Fatalf("SetPacketHold(nil): %v", err)
	}
	expectSent(t, ids, 700, 2*time.Second)
}

func TestConn_PacketHoldLoweredLimitReleasesImmediately(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	if err := conn.SetPacketHold(holdIDs(700), 10); err != nil {
		t.Fatalf("SetPacketHold: %v", err)
	}
	writeAll(t, conn, 700, 700)
	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := conn.SetPacketHold(holdIDs(700), 2); err != nil {
		t.Fatalf("SetPacketHold: %v", err)
	}
	expectSent(t, ids, 700, 2*time.Second)
	expectSent(t, ids, 700, 2*time.Second)
}

func TestConn_PacketHoldCompletesHeldPacketsOnlyOnRelease(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	var (
		mu        sync.Mutex
		completed []uint32
	)
	conn.SetWriteObserver(func(pk packet.Packet) func() {
		id := pk.(*packet.Unknown).PacketID
		return func() {
			mu.Lock()
			completed = append(completed, id)
			mu.Unlock()
		}
	})
	completions := func() []uint32 {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(completed)
	}
	if err := conn.SetPacketHold(holdIDs(700), 10); err != nil {
		t.Fatalf("SetPacketHold: %v", err)
	}
	writeAll(t, conn, 700, 701)
	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	expectSent(t, ids, 701, 2*time.Second)
	// Flush returns after the transport accepted the batch and ran its completions.
	if got := completions(); !slices.Equal(got, []uint32{701}) {
		t.Fatalf("completions before release = %v, want [701]", got)
	}
	if err := conn.SetPacketHold(nil, 0); err != nil {
		t.Fatalf("SetPacketHold(nil): %v", err)
	}
	expectSent(t, ids, 700, 2*time.Second)
	if got := completions(); !slices.Equal(got, []uint32{701, 700}) {
		t.Fatalf("completions after release = %v, want [701 700]", got)
	}
}

func TestConn_PacketHoldReleaseWaitsForSendDelay(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	if err := conn.SetPacketHold(holdIDs(700), 10); err != nil {
		t.Fatalf("SetPacketHold: %v", err)
	}
	writeAll(t, conn, 700)
	const delay = 100 * time.Millisecond
	if err := conn.SetSendDelay(delay); err != nil {
		t.Fatalf("SetSendDelay: %v", err)
	}
	start := time.Now()
	if err := conn.SetPacketHold(nil, 0); err != nil {
		t.Fatalf("SetPacketHold(nil): %v", err)
	}
	expectSent(t, ids, 700, 2*time.Second)
	if elapsed := time.Since(start); elapsed < delay {
		t.Fatalf("released packet sent after %v, want at least the %v send delay", elapsed, delay)
	}
}

func TestConn_PacketHoldCloseSendsHeld(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	if err := conn.SetPacketHold(holdIDs(700), 10); err != nil {
		t.Fatalf("SetPacketHold: %v", err)
	}
	writeAll(t, conn, 700, 701)
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	expectSent(t, ids, 701, 2*time.Second)
	expectSent(t, ids, 700, 2*time.Second)
}

func TestConn_PacketHoldAbortDiscardsHeld(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	if err := conn.SetPacketHold(holdIDs(700), 10); err != nil {
		t.Fatalf("SetPacketHold: %v", err)
	}
	writeAll(t, conn, 700)
	if err := conn.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	_ = conn.Close()
	// Abort closes the transport, which ends the reader and closes ids.
	for id := range ids {
		t.Fatalf("aborted connection sent packet %d", id)
	}
	if err := conn.SetPacketHold(holdIDs(700), 10); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SetPacketHold after shutdown = %v, want net.ErrClosed", err)
	}
}
