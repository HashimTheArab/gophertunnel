package minecraft

import (
	"errors"
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

// holdIDs returns a PacketSelector keeping the test packets with the given IDs.
func holdIDs(ids ...uint32) PacketSelector {
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
	if err := setPacketHold(conn, holdIDs(700, 702), 10); err != nil {
		t.Fatalf("setPacketHold: %v", err)
	}
	writeAll(t, conn, 700, 701, 702, 703)
	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	expectSent(t, ids, 701, 2*time.Second)
	expectSent(t, ids, 703, 2*time.Second)

	if err := setPacketHold(conn, nil, 0); err != nil {
		t.Fatalf("setPacketHold(nil): %v", err)
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
	if err := setPacketHold(conn, hold, 10); err != nil {
		t.Fatalf("setPacketHold: %v", err)
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
	if err := setPacketHold(conn, nil, 0); err != nil {
		t.Fatalf("setPacketHold(nil): %v", err)
	}
	expectSent(t, ids, 700, 2*time.Second)
}

func TestConn_PacketHoldLimitReleasesAndKeepsHolding(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	if err := setPacketHold(conn, holdIDs(700), 2); err != nil {
		t.Fatalf("setPacketHold: %v", err)
	}
	// The second held packet reaches the limit and queues both behind 701; the third is held again.
	writeAll(t, conn, 700, 701, 700, 700, 702)
	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	for _, want := range []uint32{701, 700, 700, 702} {
		expectSent(t, ids, want, 2*time.Second)
	}
	if err := setPacketHold(conn, nil, 0); err != nil {
		t.Fatalf("setPacketHold(nil): %v", err)
	}
	expectSent(t, ids, 700, 2*time.Second)
}

func TestConn_PacketHoldLoweredLimitReleasesImmediately(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	if err := setPacketHold(conn, holdIDs(700), 10); err != nil {
		t.Fatalf("setPacketHold: %v", err)
	}
	writeAll(t, conn, 700, 700)
	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := setPacketHold(conn, holdIDs(700), 2); err != nil {
		t.Fatalf("setPacketHold: %v", err)
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
	if err := setPacketHold(conn, holdIDs(700), 10); err != nil {
		t.Fatalf("setPacketHold: %v", err)
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
	if err := setPacketHold(conn, nil, 0); err != nil {
		t.Fatalf("setPacketHold(nil): %v", err)
	}
	expectSent(t, ids, 700, 2*time.Second)
	if got := completions(); !slices.Equal(got, []uint32{701, 700}) {
		t.Fatalf("completions after release = %v, want [701 700]", got)
	}
}

func TestConn_PacketHoldReleaseWaitsForSendDelay(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	if err := setPacketHold(conn, holdIDs(700), 10); err != nil {
		t.Fatalf("setPacketHold: %v", err)
	}
	writeAll(t, conn, 700)
	const delay = 100 * time.Millisecond
	if err := setSendDelay(conn, delay); err != nil {
		t.Fatalf("setSendDelay: %v", err)
	}
	start := time.Now()
	if err := setPacketHold(conn, nil, 0); err != nil {
		t.Fatalf("setPacketHold(nil): %v", err)
	}
	expectSent(t, ids, 700, 2*time.Second)
	if elapsed := time.Since(start); elapsed < delay {
		t.Fatalf("released packet sent after %v, want at least the %v send delay", elapsed, delay)
	}
}

func TestConn_PacketHoldCloseSendsHeld(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	if err := setPacketHold(conn, holdIDs(700), 10); err != nil {
		t.Fatalf("setPacketHold: %v", err)
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
	if err := setPacketHold(conn, holdIDs(700), 10); err != nil {
		t.Fatalf("setPacketHold: %v", err)
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
	if err := setPacketHold(conn, holdIDs(700), 10); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("setPacketHold after shutdown = %v, want net.ErrClosed", err)
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
	if err := setPacketHold(conn, holdIDs(700, 702), 10); err != nil {
		t.Fatalf("setPacketHold: %v", err)
	}
	// 701 and 703 stay pending, so the release lands behind them and its completions are rebased.
	writeAll(t, conn, 700, 701, 702, 703)
	if err := setPacketHold(conn, nil, 0); err != nil {
		t.Fatalf("setPacketHold(nil): %v", err)
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
	if err := setPacketHold(conn, holdIDs(700), 1); err != nil {
		t.Fatalf("setPacketHold: %v", err)
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
	if err := setSendDelay(conn, time.Hour); err != nil {
		t.Fatalf("setSendDelay: %v", err)
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
		closing := conn.holds.closed
		conn.sendMu.Unlock()
		if closing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Close did not close the hold before draining")
		}
		time.Sleep(time.Millisecond)
	}
	if err := setPacketHold(conn, holdIDs(700), 10); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("setPacketHold while closing = %v, want net.ErrClosed", err)
	}
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	<-closed
}

func TestConn_PacketHoldAbortDropsHeldReferences(t *testing.T) {
	conn, _ := newSendDelayConn(t)
	if err := setPacketHold(conn, holdIDs(700), 10); err != nil {
		t.Fatalf("setPacketHold: %v", err)
	}
	conn.SetWriteObserver(func(packet.Packet) func() { return func() {} })
	writeAll(t, conn, 700)
	if err := conn.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	_ = conn.Close()
	conn.sendMu.Lock()
	defer conn.sendMu.Unlock()
	if len(conn.holds.parked) != 0 || len(conn.holds.manual) != 0 || len(conn.bufferedSend) != 0 || len(conn.bufferedObservers) != 0 {
		t.Fatalf("after Abort and Close: %d held, %d manual holds, %d pending, %d pending completions; want none retained",
			len(conn.holds.parked), len(conn.holds.manual), len(conn.bufferedSend), len(conn.bufferedObservers))
	}
}

func TestConn_PacketHoldAbortWhileWriterBusyStillDropsHeld(t *testing.T) {
	conn, _ := newSendDelayConn(t)
	if err := setPacketHold(conn, holdIDs(700), 10); err != nil {
		t.Fatalf("setPacketHold: %v", err)
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
	conn.releaseHeldLocked(^uint64(0))
	conn.sendMu.Unlock()

	deadline := time.Now().Add(2 * time.Second)
	for {
		conn.sendMu.Lock()
		held, pending, closed := len(conn.holds.parked), len(conn.bufferedSend), conn.holds.closed
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
		case 700:
			return PacketHoldKeep
		case 701:
			return PacketHoldRelease
		default:
			return PacketHoldSend
		}
	}
	if err := setPacketHold(conn, hold, 3); err != nil {
		t.Fatalf("setPacketHold: %v", err)
	}
	// 702 overtakes the held 700; 701 releases it first; the third held 700 hits the limit.
	writeAll(t, conn, 700, 702, 700, 701, 700, 700, 700)
	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	for range 7 {
		select {
		case <-ids:
		case <-time.After(2 * time.Second):
			t.Fatal("packets were not sent")
		}
	}
	want := []string{"h700", "w702", "h700", "r700", "r700", "w701", "h700", "h700", "h700", "r700", "r700", "r700"}
	if got := log.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("queue events = %v, want %v", got, want)
	}
}

// A held packet the connection discards never joins the send order.
func TestConn_QueueObserverSkipsDiscardedPackets(t *testing.T) {
	conn, _ := newSendDelayConn(t)
	var log queueLog
	conn.SetQueueObserver(log.observer)
	if err := setPacketHold(conn, holdIDs(700), 10); err != nil {
		t.Fatalf("setPacketHold: %v", err)
	}
	writeAll(t, conn, 700)
	if err := conn.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if got := log.snapshot(); !slices.Equal(got, []string{"h700"}) {
		t.Fatalf("queue events = %v, want only the held capture", got)
	}
}

// A packet two manual holds keep waits for both, while each hold's own packets go once it lets go.
func TestPacketHold_PacketKeptByTwoHoldsWaitsForBoth(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	first, second := conn.NewPacketHold(), conn.NewPacketHold()
	if err := first.Set(PacketHoldRule{Select: holdIDs(700, 701), Limit: 10}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := second.Set(PacketHoldRule{Select: holdIDs(701, 702), Limit: 10}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	writeAll(t, conn, 700, 701, 702, 703)
	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	expectSent(t, ids, 703, 2*time.Second)

	if err := first.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	mustFlush(t, conn)
	expectSent(t, ids, 700, 2*time.Second)
	expectNothingSent(t, ids, 50*time.Millisecond)

	if err := second.Set(PacketHoldRule{}); err != nil {
		t.Fatalf("Set(zero): %v", err)
	}
	mustFlush(t, conn)
	expectSent(t, ids, 701, 2*time.Second)
	expectSent(t, ids, 702, 2*time.Second)
}

// Each hold counts the packets it keeps toward its own limit, and a hold reaching its limit leaves the
// packets another hold keeps in place.
func TestPacketHold_LimitsAreCountedPerHold(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	first, second := conn.NewPacketHold(), conn.NewPacketHold()
	if err := first.Set(PacketHoldRule{Select: holdIDs(700, 701), Limit: 2}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := second.Set(PacketHoldRule{Select: holdIDs(701), Limit: 10}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	// The second packet reaches the first hold's limit; 701 is still kept by the second hold.
	writeAll(t, conn, 701, 700, 702)
	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	expectSent(t, ids, 700, 2*time.Second)
	expectSent(t, ids, 702, 2*time.Second)
	expectNothingSent(t, ids, 50*time.Millisecond)
	if err := second.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	mustFlush(t, conn)
	expectSent(t, ids, 701, 2*time.Second)
}

// Discard drops what the hold keeps, never completes or reports it, and leaves the hold holding.
func TestPacketHold_DiscardDropsKeptPacketsAndKeepsHolding(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	var log queueLog
	conn.SetQueueObserver(log.observer)
	var completed []uint32
	conn.SetWriteObserver(func(pk packet.Packet) func() {
		id := pk.(*packet.Unknown).PacketID
		return func() { completed = append(completed, id) }
	})
	hold, other := conn.NewPacketHold(), conn.NewPacketHold()
	if err := hold.Set(PacketHoldRule{Select: holdIDs(700, 701), Limit: 10}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := other.Set(PacketHoldRule{Select: holdIDs(701, 702), Limit: 2}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	writeAll(t, conn, 700, 701)
	hold.Discard()

	// The other hold no longer counts the discarded 701, so one more 702 stays under its limit.
	writeAll(t, conn, 702, 700, 703)
	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	expectSent(t, ids, 703, 2*time.Second)
	if err := hold.Set(PacketHoldRule{}); err != nil {
		t.Fatalf("Set(zero): %v", err)
	}
	mustFlush(t, conn)
	expectSent(t, ids, 700, 2*time.Second)
	if err := other.Set(PacketHoldRule{}); err != nil {
		t.Fatalf("Set(zero): %v", err)
	}
	mustFlush(t, conn)
	expectSent(t, ids, 702, 2*time.Second)

	conn.sendMu.Lock()
	got := slices.Clone(completed)
	conn.sendMu.Unlock()
	if !slices.Equal(got, []uint32{703, 700, 702}) {
		t.Fatalf("completions = %v, want only the packets sent", got)
	}
	want := []string{"h700", "h701", "h702", "h700", "w703", "r700", "r702"}
	if got := log.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("queue events = %v, want %v", got, want)
	}
}

// A SelectableOnly hold sees only the packets written with WritePacketSelectable.
func TestPacketHold_SelectableOnlySeesSelectableWritesAlone(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	hold := conn.NewPacketHold()
	if err := hold.Set(PacketHoldRule{Select: holdIDs(700), Limit: 10, SelectableOnly: true}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := conn.WritePacketSelectable(testPacket(700)); err != nil {
		t.Fatalf("WritePacketSelectable: %v", err)
	}
	writeAll(t, conn, 700, 701)
	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	expectSent(t, ids, 700, 2*time.Second)
	expectSent(t, ids, 701, 2*time.Second)
	if err := hold.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	// Release leaves the batch boundary to its caller.
	expectNothingSent(t, ids, 50*time.Millisecond)
	mustFlush(t, conn)
	expectSent(t, ids, 700, 2*time.Second)
}

// With a delay on top, a packet a manual hold lets go of waits the full delay from then, behind packets
// that went ahead of it earlier, so a packet the hold let through stays ahead however the release is
// timed.
func TestPacketHold_ReleasedPacketWaitsTheDelayBehindPacketsLetThrough(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	var log queueLog
	conn.SetQueueObserver(log.observer)
	manual, delay := conn.NewPacketHold(), conn.NewPacketHold()
	if err := manual.Set(PacketHoldRule{Select: holdIDs(700), Limit: 10}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	const d = 150 * time.Millisecond
	if err := delay.Set(PacketHoldRule{Delay: d}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	writeAll(t, conn, 700)
	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	time.Sleep(d / 3)
	writeAll(t, conn, 701)
	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	start := time.Now()
	if err := manual.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	mustFlush(t, conn)
	expectSent(t, ids, 701, 2*time.Second)
	expectSent(t, ids, 700, 2*time.Second)
	if elapsed := time.Since(start); elapsed < d {
		t.Fatalf("released packet sent %v after the release, want at least the %v delay", elapsed, d)
	}
	if got, want := log.snapshot(), []string{"h700", "w701", "r700"}; !slices.Equal(got, want) {
		t.Fatalf("queue events = %v, want %v", got, want)
	}
}

// The delay is the largest any hold sets, and once no hold delays any more, everything delayed is sent.
func TestPacketHold_DelayIsTheLargestOfAnyHold(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	short, long := conn.NewPacketHold(), conn.NewPacketHold()
	if err := short.Set(PacketHoldRule{Delay: time.Millisecond}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := long.Set(PacketHoldRule{Delay: time.Hour}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := conn.WritePacketImmediate(testPacket(700)); err != nil {
		t.Fatalf("WritePacketImmediate: %v", err)
	}
	expectNothingSent(t, ids, 50*time.Millisecond)
	if err := long.Set(PacketHoldRule{}); err != nil {
		t.Fatalf("Set(zero): %v", err)
	}
	// Lowering the delay never reorders, so the packet keeps its due time until no delay is left.
	expectNothingSent(t, ids, 50*time.Millisecond)
	if err := short.Set(PacketHoldRule{}); err != nil {
		t.Fatalf("Set(zero): %v", err)
	}
	expectSent(t, ids, 700, 2*time.Second)
}

func TestPacketHold_SetRejectsARuleThatDelaysAndSelects(t *testing.T) {
	conn, _ := newSendDelayConn(t)
	if err := conn.NewPacketHold().Set(PacketHoldRule{Select: holdIDs(700), Delay: time.Second}); err == nil {
		t.Fatal("Set accepted a rule that both delays and selects")
	}
}

func TestPacketHold_SetRefusesMoreManualHoldsThanTheConnCanTrack(t *testing.T) {
	conn, _ := newSendDelayConn(t)
	holds := make([]*PacketHold, maxManualHolds)
	for i := range holds {
		holds[i] = conn.NewPacketHold()
		if err := holds[i].Set(PacketHoldRule{Select: holdIDs(700)}); err != nil {
			t.Fatalf("Set hold %d: %v", i, err)
		}
	}
	extra := conn.NewPacketHold()
	if err := extra.Set(PacketHoldRule{Select: holdIDs(700)}); !errors.Is(err, errTooManyHolds) {
		t.Fatalf("Set beyond the limit = %v, want errTooManyHolds", err)
	}
	// A hold that stops holding frees its place.
	if err := holds[3].Set(PacketHoldRule{}); err != nil {
		t.Fatalf("Set(zero): %v", err)
	}
	if err := extra.Set(PacketHoldRule{Select: holdIDs(700)}); err != nil {
		t.Fatalf("Set after a hold stopped: %v", err)
	}
}

func TestPacketHold_NilHoldsNothing(t *testing.T) {
	var hold *PacketHold
	if err := hold.Set(PacketHoldRule{Select: holdIDs(700)}); err != nil {
		t.Fatalf("Set on nil = %v, want nil", err)
	}
	if err := hold.Release(); err != nil {
		t.Fatalf("Release on nil = %v, want nil", err)
	}
	hold.Discard()
}
