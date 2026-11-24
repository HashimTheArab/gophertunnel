package minecraft

import (
	"net"

	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// PacketHold decides what SetPacketHold does with each packet written. It runs synchronously under the
// connection's packet write lock, once per logical packet, so it must be short and nonblocking, must not
// write to or reconfigure the connection, and must not retain the packet.
type PacketHold func(packet.Packet) PacketHoldDecision

// PacketHoldDecision is what a PacketHold does with one packet.
type PacketHoldDecision uint8

const (
	// PacketHoldSend sends the packet as usual, so it overtakes the packets already held.
	PacketHoldSend PacketHoldDecision = iota
	// PacketHoldKeep holds the packet behind the packets already held.
	PacketHoldKeep
	// PacketHoldRelease queues everything held, in order, behind the packets already pending, then the
	// packet itself, and keeps holding. A packet that must not overtake held packets, but must not wait
	// either, uses it. Written with WritePacketDirect, the packet's own batch still goes first.
	PacketHoldRelease
)

// SetPacketHold holds each packet written afterwards that hold keeps, marshaled exactly as it would be
// sent, while every other packet is sent as usual, so held packets end up behind packets written after
// them. Once limit packets are held, all of them are queued, in the order they were written, behind the
// packets already pending, and holding continues; a limit below one is treated as one. A nil hold queues
// everything held and stops holding. Queued packets go out with the next Flush, which SetPacketHold runs
// itself whenever it queues held packets, and then wait for any SendDelay like every other batch.
//
// The WriteObserver sees a held packet when it is written; its completion runs once the packet actually
// reaches the transport. A QueueObserver learns when the hold releases it into the send order. Close sends what is held, Abort discards it, and a hold set after shutdown holds
// nothing. It returns any failure flushing the released packets, including an earlier send failure.
func (conn *Conn) SetPacketHold(hold PacketHold, limit int) error {
	conn.encMu.Lock()
	defer conn.encMu.Unlock()
	conn.sendMu.Lock()
	if conn.ctx == nil || conn.ctx.Err() != nil || conn.hold.closed {
		conn.hold.close()
		conn.sendMu.Unlock()
		return net.ErrClosed
	}
	conn.hold.set(hold, limit)
	released := hold == nil || conn.hold.count >= conn.hold.limit
	if released {
		released = conn.releaseHeldLocked()
	}
	conn.sendMu.Unlock()
	if !released {
		return nil
	}
	return conn.flushLocked()
}

// packetHold is the selector and the marshaled packets it holds. The connection's sendMu guards it.
type packetHold struct {
	selector PacketHold
	limit    int
	// packets are the held wire packets, and observers their completions, indexed as in the pending batch.
	packets   [][]byte
	observers []packetCompletion
	// released are the QueueObserver's functions for the held packets, in the order they were held.
	released []func()
	// count is the number of logical packets held, which can be fewer than the wire packets in packets.
	count int
	// closed is set once the connection shuts down; a closed hold selects nothing.
	closed bool
}

// close drops everything held and refuses later holds.
func (h *packetHold) close() {
	*h = packetHold{closed: true}
}

// dropHeld discards held packets for Abort, together with the pending batch, which no flush sends once
// the connection is cancelled. Abort must never wait, even when its own caller holds sendMu, so if sendMu
// is busy, a goroutine drops them as soon as the holder lets go. A writer that passed its context check
// before the abort therefore cannot leave packets behind, including held packets it released into the
// pending batch.
func (conn *Conn) dropHeld() {
	if conn.sendMu.TryLock() {
		conn.dropUnsentLocked()
		conn.sendMu.Unlock()
		return
	}
	go func() {
		conn.sendMu.Lock()
		conn.dropUnsentLocked()
		conn.sendMu.Unlock()
	}()
}

// dropUnsentLocked closes the hold and clears the pending batch. The caller holds sendMu.
func (conn *Conn) dropUnsentLocked() {
	conn.hold.close()
	clear(conn.bufferedSend)
	conn.bufferedSend, conn.bufferedObservers = conn.bufferedSend[:0], nil
}

// dropPendingIfClosed clears the pending batch once the connection is cancelled, when no later flush can
// send it. Close calls it after its final flush, so held packets it released just before an Abort are not
// kept on the closed connection.
func (conn *Conn) dropPendingIfClosed() {
	if conn.ctx == nil || conn.ctx.Err() == nil {
		return
	}
	conn.sendMu.Lock()
	clear(conn.bufferedSend)
	conn.bufferedSend, conn.bufferedObservers = conn.bufferedSend[:0], nil
	conn.sendMu.Unlock()
}

// closeHold queues everything held for Close's final flush and stops holding, so a SetPacketHold racing
// the rest of Close gets net.ErrClosed instead of holding packets nobody will send. A connection already
// cancelled drops what it holds.
func (conn *Conn) closeHold() {
	conn.sendMu.Lock()
	defer conn.sendMu.Unlock()
	if conn.ctx != nil && conn.ctx.Err() == nil {
		conn.releaseHeldLocked()
	}
	conn.hold.close()
}

// set replaces the selector and its limit without touching what is already held.
func (h *packetHold) set(hold PacketHold, limit int) {
	h.selector, h.limit = hold, max(limit, 1)
}

// decide reports what happens to pk. A closed or unset hold sends everything.
func (h *packetHold) decide(pk packet.Packet) PacketHoldDecision {
	if h.selector == nil {
		return PacketHoldSend
	}
	return h.selector(pk)
}

// releaseHeldLocked queues every held packet, in order, behind the pending batch and reports whether any
// were queued. The caller holds sendMu.
func (conn *Conn) releaseHeldLocked() bool {
	h := &conn.hold
	if len(h.packets) == 0 {
		h.count = 0
		return false
	}
	offset := len(conn.bufferedSend)
	conn.bufferedSend = append(conn.bufferedSend, h.packets...)
	for _, observer := range h.observers {
		observer.after += offset
		conn.bufferedObservers = append(conn.bufferedObservers, observer)
	}
	clear(h.packets)
	clear(h.observers)
	h.packets, h.observers, h.count = h.packets[:0], h.observers[:0], 0
	// The packets are queued now, so whatever is written next goes out behind them.
	for i, released := range h.released {
		h.released[i] = nil
		released()
	}
	h.released = h.released[:0]
	return true
}
