package minecraft

import (
	"net"

	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// PacketHold selects the packets SetPacketHold keeps from being sent. It runs synchronously under the
// connection's packet write lock, once per logical packet, so it must be short and nonblocking, must not
// write to or reconfigure the connection, and must not retain the packet.
type PacketHold func(packet.Packet) bool

// SetPacketHold holds each packet written afterwards that hold selects, marshaled exactly as it would be
// sent, while every other packet is sent as usual, so held packets end up behind packets written after
// them. Once limit packets are held, all of them are queued, in the order they were written, behind the
// packets already pending, and holding continues; a limit below one is treated as one. A nil hold queues
// everything held and stops holding. Queued packets go out with the next Flush, which SetPacketHold runs
// itself whenever it queues held packets, and then wait for any SendDelay like every other batch.
//
// The WriteObserver sees a held packet when it is written; its completion runs once the packet actually
// reaches the transport. Close sends what is held, Abort discards it, and a hold set after shutdown holds
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
	// count is the number of logical packets held, which can be fewer than the wire packets in packets.
	count int
	// closed is set once the connection shuts down; a closed hold selects nothing.
	closed bool
}

// close drops everything held and refuses later holds.
func (h *packetHold) close() {
	*h = packetHold{closed: true}
}

// dropHeld discards held packets for Abort without waiting: if a writer holds sendMu, the next writer to
// find the connection closed drops them instead.
func (conn *Conn) dropHeld() {
	if conn.sendMu.TryLock() {
		conn.hold.close()
		conn.sendMu.Unlock()
	}
}

// set replaces the selector and its limit without touching what is already held.
func (h *packetHold) set(hold PacketHold, limit int) {
	h.selector, h.limit = hold, max(limit, 1)
}

// selects reports whether pk is held.
func (h *packetHold) selects(pk packet.Packet) bool {
	return h.selector != nil && h.selector(pk)
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
	return true
}
