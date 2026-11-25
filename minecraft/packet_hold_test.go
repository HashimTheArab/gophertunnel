package minecraft

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// holdIDs returns a PacketHold keeping the test packets with the given IDs.
func holdIDs(ids ...uint32) PacketHold {
	return func(pk packet.Packet) PacketHoldDecision {
		if unknown, ok := pk.(*packet.Unknown); ok && slices.Contains(ids, unknown.PacketID) {
			return PacketHoldKeep
		}
		return PacketHoldSend
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

func TestConn_PacketHoldReleaseSendsHeldFirstAndKeepsHolding(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	hold := func(pk packet.Packet) PacketHoldDecision {
		switch pk.(*packet.Unknown).PacketID {
		case 700:
			return PacketHoldKeep
		case 701:
			return PacketHoldRelease
		default:
			return PacketHoldSend
		}
	}
	if err := conn.SetPacketHold(hold, 10); err != nil {
		t.Fatalf("SetPacketHold: %v", err)
	}
	writeAll(t, conn, 700, 702, 700, 701, 700, 703)
	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	// 702 was sent as usual, so it went ahead of the 700s held before it; 701 waited for them instead.
	expectSent(t, ids, 702, 2*time.Second)
	expectSent(t, ids, 700, 2*time.Second)
	expectSent(t, ids, 700, 2*time.Second)
	expectSent(t, ids, 701, 2*time.Second)
	expectSent(t, ids, 703, 2*time.Second)

	// The 700 written after 701 is still held.
	if err := conn.SetPacketHold(nil, 0); err != nil {
		t.Fatalf("SetPacketHold(nil): %v", err)
	}
	expectSent(t, ids, 700, 2*time.Second)
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

func TestConn_PacketHoldRebasesCompletionsBehindPendingPackets(t *testing.T) {
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
	if err := conn.SetPacketHold(holdIDs(700, 702), 10); err != nil {
		t.Fatalf("SetPacketHold: %v", err)
	}
	// 701 and 703 stay pending, so the release lands behind them and its completions are rebased.
	writeAll(t, conn, 700, 701, 702, 703)
	if err := conn.SetPacketHold(nil, 0); err != nil {
		t.Fatalf("SetPacketHold(nil): %v", err)
	}
	for _, want := range []uint32{701, 703, 700, 702} {
		expectSent(t, ids, want, 2*time.Second)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(completed, []uint32{701, 703, 700, 702}) {
		t.Fatalf("completions = %v, want each packet completed once, in wire order", completed)
	}
}

func TestConn_PacketHoldLimitFromADirectWriteQueuesBehindPending(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	if err := conn.SetPacketHold(holdIDs(700), 1); err != nil {
		t.Fatalf("SetPacketHold: %v", err)
	}
	writeAll(t, conn, 701)
	// The direct write's only packet is held and reaches the limit at once, so it is queued behind 701.
	if err := conn.WritePacketDirect(testPacket(700), testPacket(702)); err != nil {
		t.Fatalf("WritePacketDirect: %v", err)
	}
	expectSent(t, ids, 702, 2*time.Second)
	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	expectSent(t, ids, 701, 2*time.Second)
	expectSent(t, ids, 700, 2*time.Second)
}

func TestConn_PacketHoldRefusedOnceCloseStarts(t *testing.T) {
	client, peer := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = peer.Close()
	})
	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	// A batch held by the send delay makes Close block on the unread pipe while it drains.
	if err := conn.SetSendDelay(time.Hour); err != nil {
		t.Fatalf("SetSendDelay: %v", err)
	}
	if err := conn.WritePacketImmediate(testPacket(701)); err != nil {
		t.Fatalf("WritePacketImmediate: %v", err)
	}
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		_ = conn.Close()
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn.sendMu.Lock()
		closing := conn.hold.closed
		conn.sendMu.Unlock()
		if closing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Close did not close the hold before draining")
		}
		time.Sleep(time.Millisecond)
	}
	if err := conn.SetPacketHold(holdIDs(700), 10); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SetPacketHold while closing = %v, want net.ErrClosed", err)
	}
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	<-closed
}

func TestConn_PacketHoldAbortDropsHeldReferences(t *testing.T) {
	conn, _ := newSendDelayConn(t)
	if err := conn.SetPacketHold(holdIDs(700), 10); err != nil {
		t.Fatalf("SetPacketHold: %v", err)
	}
	conn.SetWriteObserver(func(packet.Packet) func() { return func() {} })
	writeAll(t, conn, 700)
	if err := conn.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	_ = conn.Close()
	conn.sendMu.Lock()
	defer conn.sendMu.Unlock()
	if len(conn.hold.packets) != 0 || len(conn.hold.observers) != 0 || len(conn.bufferedSend) != 0 || len(conn.bufferedObservers) != 0 {
		t.Fatalf("after Abort and Close: %d held, %d held completions, %d pending, %d pending completions; want none retained",
			len(conn.hold.packets), len(conn.hold.observers), len(conn.bufferedSend), len(conn.bufferedObservers))
	}
}

func TestConn_PacketHoldAbortWhileWriterBusyStillDropsHeld(t *testing.T) {
	conn, _ := newSendDelayConn(t)
	if err := conn.SetPacketHold(holdIDs(700), 10); err != nil {
		t.Fatalf("SetPacketHold: %v", err)
	}
	writeAll(t, conn, 700, 700)
	// A writer holds sendMu while Abort runs, so Abort cannot drop the held packets itself.
	conn.sendMu.Lock()
	if err := conn.Abort(); err != nil {
		conn.sendMu.Unlock()
		t.Fatalf("Abort: %v", err)
	}
	// The writer passed its context check before the abort and released what was held into the pending
	// batch, as a PacketHoldRelease decision or the limit does. No flush sends it any more.
	conn.releaseHeldLocked()
	conn.sendMu.Unlock()

	deadline := time.Now().Add(2 * time.Second)
	for {
		conn.sendMu.Lock()
		held, pending, closed := len(conn.hold.packets), len(conn.bufferedSend), conn.hold.closed
		conn.sendMu.Unlock()
		if held == 0 && pending == 0 && closed {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after Abort with sendMu busy: %d packets still held, %d pending, closed=%v", held, pending, closed)
		}
		time.Sleep(time.Millisecond)
	}
}

// queueLog records what a QueueObserver sees: "w<id>" for a packet joining the send order as it is
// written, "h<id>" for a held capture and "r<id>" for its release.
type queueLog struct {
	mu     sync.Mutex
	events []string
}

func (l *queueLog) add(event string) {
	l.mu.Lock()
	l.events = append(l.events, event)
	l.mu.Unlock()
}

func (l *queueLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.events)
}

func (l *queueLog) observer(pk packet.Packet, held bool) func() {
	id := pk.(*packet.Unknown).PacketID
	if !held {
		l.add("w" + strconv.Itoa(int(id)))
		return func() { l.add("ignored") }
	}
	l.add("h" + strconv.Itoa(int(id)))
	return func() { l.add("r" + strconv.Itoa(int(id))) }
}

// A QueueObserver learns when each packet joins the send order: as it is written, or for a held packet
// when the hold releases it, in order and before anything written after the release.
func TestConn_QueueObserverSeesHeldPacketsJoinTheSendOrder(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	var log queueLog
	conn.SetQueueObserver(log.observer)
	hold := func(pk packet.Packet) PacketHoldDecision {
		switch pk.(*packet.Unknown).PacketID {
		case 701:
			return PacketHoldRelease
		case 702:
			return PacketHoldSend
		default:
			return PacketHoldKeep
		}
	}
	if err := conn.SetPacketHold(hold, 3); err != nil {
		t.Fatalf("SetPacketHold: %v", err)
	}
	// 702 overtakes the held 700; 701 releases 700 and 703 first; the third held packet, 706, hits the limit.
	writeAll(t, conn, 700, 702, 703, 701, 704, 705, 706)
	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	var sent []uint32
	for range 7 {
		select {
		case id := <-ids:
			sent = append(sent, id)
		case <-time.After(2 * time.Second):
			t.Fatal("packets were not sent")
		}
	}
	if want := []uint32{702, 700, 703, 701, 704, 705, 706}; !slices.Equal(sent, want) {
		t.Fatalf("sent %v, want %v", sent, want)
	}
	want := []string{"h700", "w702", "h703", "r700", "r703", "w701", "h704", "h705", "h706", "r704", "r705", "r706"}
	if got := log.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("queue events = %v, want %v", got, want)
	}
}

// A held packet the connection discards never joins the send order, including one a writer that was
// already past its context check releases after the Abort.
func TestConn_QueueObserverSkipsDiscardedPackets(t *testing.T) {
	for _, writerBusy := range []bool{false, true} {
		t.Run(fmt.Sprintf("writerBusy=%t", writerBusy), func(t *testing.T) {
			conn, _ := newSendDelayConn(t)
			var log queueLog
			conn.SetQueueObserver(log.observer)
			if err := conn.SetPacketHold(holdIDs(700), 10); err != nil {
				t.Fatalf("SetPacketHold: %v", err)
			}
			writeAll(t, conn, 700)
			if writerBusy {
				conn.sendMu.Lock()
			}
			if err := conn.Abort(); err != nil {
				t.Fatalf("Abort: %v", err)
			}
			if writerBusy {
				// The writer releases what is held, as a PacketHoldRelease decision or the limit does.
				conn.releaseHeldLocked()
				conn.sendMu.Unlock()
			}
			if got := log.snapshot(); !slices.Equal(got, []string{"h700"}) {
				t.Fatalf("queue events = %v, want only the held capture", got)
			}
		})
	}
}
