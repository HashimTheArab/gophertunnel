package minecraft

import (
	"errors"
	"net"
	"slices"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// PacketSelector decides what a manual PacketHold does with each packet written. It runs synchronously
// under the connection's packet write lock, once per logical packet, so it must be short and nonblocking,
// must not write to or reconfigure the connection, and must not retain the packet.
type PacketSelector func(packet.Packet) PacketHoldDecision

// PacketHoldDecision is what a manual PacketHold does with one packet.
type PacketHoldDecision uint8

const (
	// PacketHoldSend lets the packet through this hold, so it overtakes the packets the hold keeps.
	PacketHoldSend PacketHoldDecision = iota
	// PacketHoldKeep keeps the packet behind the packets the hold already keeps.
	PacketHoldKeep
	// PacketHoldRelease lets go of everything the hold keeps, in order, behind the packets already
	// pending, then lets the packet itself through, and keeps holding. A packet that must not overtake
	// held packets, but must not wait either, uses it. Written with WritePacketDirect, the packet's own
	// batch still goes first.
	PacketHoldRelease
)

// maxManualHolds is how many PacketHolds with a manual rule one Conn can have at a time.
const maxManualHolds = 64

// errTooManyHolds is returned by PacketHold.Set when a Conn already has maxManualHolds manual holds.
var errTooManyHolds = errors.New("minecraft: too many manual packet holds on one connection")

// PacketHoldRule configures a PacketHold. The zero rule holds nothing.
//
// A rule with a Select is manual: each packet written afterwards that Select keeps waits, marshaled
// exactly as it would be sent, until the hold lets go of it, while every other packet goes on as usual, so
// held packets end up behind packets written after them. A rule with a Delay holds every packet the Conn
// sends, raw writes included, for Delay after the flush that submits it, in the order it was sent.
type PacketHoldRule struct {
	// Select chooses what a manual hold keeps.
	Select PacketSelector
	// Limit lets go of everything a manual hold keeps once it keeps Limit packets, and holding continues.
	// A limit below one is treated as one.
	Limit int
	// SelectableOnly shows Select only the packets written with WritePacketSelectable. Every other packet
	// goes on as if Select let it through.
	SelectableOnly bool
	// Delay adds latency to everything the Conn sends. It cannot be combined with a manual rule.
	Delay time.Duration
}

// manual reports whether the rule keeps selected packets until they are let go of.
func (r PacketHoldRule) manual() bool { return r.Select != nil }

// PacketHold holds packets written to the Conn that created it according to its rule. Several holds can
// be set on one Conn, each by its own owner:
//
//   - A packet waits while any manual hold keeps it. A hold letting go of a packet another hold still
//     keeps leaves it held; once no hold keeps it, it is queued behind the packets already pending, with
//     the other packets let go of at the same time, in the order they were written.
//   - Packets no manual hold keeps, and packets let go of, then wait for the largest Delay of any hold,
//     counted from the flush that submits them. The delay never reorders: after it is lowered, new
//     packets still wait for those submitted before them. A delay applies to the packets as encoded, so
//     a packet let go of waits the full delay from that flush.
//
// The WriteObserver sees a held packet when it is written; its completion runs once the packet actually
// reaches the transport. A QueueObserver learns when a manual hold lets it go into the send order. Close
// sends everything held, Abort discards it, and a hold set after shutdown holds nothing.
//
// A PacketHold is safe for concurrent use. Create one with NewPacketHold. A nil *PacketHold holds nothing
// and its methods do nothing, so a stand-in for a Conn that cannot hold packets can return one.
type PacketHold struct {
	conn *Conn

	// The fields below are guarded by conn.sendMu.

	rule  PacketHoldRule
	limit int
	// bit marks the packets this hold keeps while its rule is manual, and is zero otherwise.
	bit uint64
	// count is the number of logical packets this hold keeps.
	count int
}

// NewPacketHold returns a hold on conn that holds nothing until its rule is set.
func (conn *Conn) NewPacketHold() *PacketHold {
	return &PacketHold{conn: conn}
}

// Set replaces the hold's rule. Packets the hold already keeps stay held while the new rule is manual
// too, and are let go of otherwise; a manual limit at or below what the hold keeps lets go of all of
// them. Packets let go of are queued behind the packets already pending and go out with the next Flush:
// Set never flushes, so its caller decides where the batch ends. A lower largest Delay applies to what is
// sent afterwards; once no hold has a Delay, everything already delayed is sent. It returns any failure
// sending delayed packets, including an earlier send failure, and net.ErrClosed once the Conn shuts down.
func (h *PacketHold) Set(rule PacketHoldRule) error {
	rule.Delay = max(rule.Delay, 0)
	if rule.Delay > 0 && (rule.manual() || rule.Limit != 0 || rule.SelectableOnly) {
		return errors.New("minecraft: a packet hold rule cannot both delay and select packets")
	}
	if h == nil {
		return nil
	}
	conn := h.conn
	// holdMu serializes Sets, so the delay published below stays the one the holds need until the rule is
	// applied.
	conn.holdMu.Lock()
	defer conn.holdMu.Unlock()
	conn.sendMu.Lock()
	holds := &conn.holds
	if conn.closedLocked() {
		holds.close()
		conn.sendMu.Unlock()
		return net.ErrClosed
	}
	if rule.manual() && h.bit == 0 && ^holds.used == 0 {
		conn.sendMu.Unlock()
		return errTooManyHolds
	}
	delay := holds.delayWith(h, rule.Delay)
	conn.sendMu.Unlock()
	// Publish the delay before applying the rule: a Flush racing this Set must not submit the packets the
	// rule lets go of under the previous delay. Publishing can write delayed packets to the transport, so
	// it runs without sendMu.
	err := conn.delay.set(delay)

	conn.sendMu.Lock()
	defer conn.sendMu.Unlock()
	if conn.closedLocked() {
		holds.close()
		return errors.Join(err, net.ErrClosed)
	}
	switch {
	case rule.manual() && h.bit == 0:
		free := ^holds.used
		h.bit = free & -free
		holds.used |= h.bit
		holds.manual = append(holds.manual, h)
	case !rule.manual() && h.bit != 0:
		conn.releaseHeldLocked(h.bit)
		holds.used &^= h.bit
		holds.manual = slices.DeleteFunc(holds.manual, func(other *PacketHold) bool { return other == h })
		h.bit = 0
	}
	wasDelayed, delayed := h.rule.Delay > 0, rule.Delay > 0
	if wasDelayed != delayed {
		if delayed {
			holds.delayed = append(holds.delayed, h)
		} else {
			holds.delayed = slices.DeleteFunc(holds.delayed, func(other *PacketHold) bool { return other == h })
		}
	}
	h.rule, h.limit = rule, max(rule.Limit, 1)
	if h.bit != 0 && h.count >= h.limit {
		conn.releaseHeldLocked(h.bit)
	}
	return err
}

// Release lets go of everything the hold keeps and keeps holding, like PacketHoldRelease. The packets it
// lets go of are queued behind the packets already pending and go out with the next Flush: Release never
// flushes, so its caller decides where the batch ends. It returns net.ErrClosed once the Conn shuts down.
func (h *PacketHold) Release() error {
	if h == nil {
		return nil
	}
	conn := h.conn
	conn.sendMu.Lock()
	defer conn.sendMu.Unlock()
	if conn.closedLocked() {
		return net.ErrClosed
	}
	if h.bit != 0 {
		conn.releaseHeldLocked(h.bit)
	}
	return nil
}

// Discard drops everything the hold keeps without sending it, including packets other holds keep too,
// and keeps holding. Discarded packets never complete and never join the send order.
func (h *PacketHold) Discard() {
	if h == nil {
		return
	}
	conn := h.conn
	conn.sendMu.Lock()
	defer conn.sendMu.Unlock()
	if h.bit != 0 {
		conn.holds.discard(h.bit)
	}
}

// packetHolds is a Conn's holds and the packets its manual holds keep. The connection's sendMu guards it.
type packetHolds struct {
	// manual are the holds with a manual rule, in the order they became manual, and used their bits.
	manual []*PacketHold
	used   uint64
	// delayed are the holds with a Delay.
	delayed []*PacketHold
	// parked are the held packets in the order they were written.
	parked []parkedPacket
	// scratch collects the wire packets of the logical packet being held.
	scratch [][]byte
	// closed is set once the connection shuts down; a closed Conn holds nothing.
	closed bool
}

// parkedPacket is one held logical packet: its wire packets, its WriteObserver completion and
// QueueObserver release, and the bits of the holds keeping it.
type parkedPacket struct {
	data     []byte
	extra    [][]byte
	sent     func()
	released func()
	keptBy   uint64
}

// delayWith returns the largest Delay of any hold once hold's Delay is d.
func (h *packetHolds) delayWith(hold *PacketHold, d time.Duration) time.Duration {
	delay := d
	for _, other := range h.delayed {
		if other != hold {
			delay = max(delay, other.rule.Delay)
		}
	}
	return delay
}

// closedLocked reports whether the Conn has shut down, so its holds hold nothing. The caller holds sendMu.
func (conn *Conn) closedLocked() bool {
	return conn.ctx == nil || conn.ctx.Err() != nil || conn.holds.closed
}

// close drops everything held and refuses later holds.
func (h *packetHolds) close() {
	for _, hold := range h.manual {
		hold.bit, hold.count = 0, 0
	}
	clear(h.parked)
	clear(h.scratch)
	*h = packetHolds{closed: true}
}

// discard drops the packets any hold in mask keeps, and stops counting them for the other holds.
func (h *packetHolds) discard(mask uint64) {
	h.parked = slices.DeleteFunc(h.parked, func(p parkedPacket) bool {
		if p.keptBy&mask == 0 {
			return false
		}
		h.uncount(p.keptBy)
		return true
	})
}

// uncount stops counting one packet for each hold in mask.
func (h *packetHolds) uncount(mask uint64) {
	for _, hold := range h.manual {
		if mask&hold.bit != 0 {
			hold.count--
		}
	}
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

// dropUnsentLocked closes the holds and clears the pending batch. The caller holds sendMu.
func (conn *Conn) dropUnsentLocked() {
	conn.holds.close()
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

// closeHold queues everything held for Close's final flush and stops holding, so a Set racing the rest of
// Close gets net.ErrClosed instead of holding packets nobody will send. A connection already cancelled
// drops what it holds.
func (conn *Conn) closeHold() {
	conn.sendMu.Lock()
	defer conn.sendMu.Unlock()
	if conn.ctx != nil && conn.ctx.Err() == nil {
		conn.releaseHeldLocked(^uint64(0))
	}
	conn.holds.close()
}

// selectLocked asks every manual hold what to do with pk, and returns the bits of the holds keeping it and
// of the holds letting go of what they keep before pk. The caller lets go of those in one release, together
// with any hold pk fills, so everything one write releases leaves in the order it was written. The caller
// holds sendMu.
func (conn *Conn) selectLocked(pk packet.Packet, selectable bool) (keptBy, released uint64) {
	for _, hold := range conn.holds.manual {
		if hold.rule.SelectableOnly && !selectable {
			continue
		}
		switch hold.rule.Select(pk) {
		case PacketHoldKeep:
			keptBy |= hold.bit
		case PacketHoldRelease:
			released |= hold.bit
		}
	}
	return keptBy, released
}

// parkLocked keeps the logical packet whose wire packets are in holds.scratch for the holds in keptBy,
// then lets go, in one release, of what the holds in release keep and of every hold it fills. The caller
// holds sendMu.
func (conn *Conn) parkLocked(keptBy, release uint64, sent, released func()) {
	holds := &conn.holds
	p := parkedPacket{data: holds.scratch[0], sent: sent, released: released, keptBy: keptBy}
	if len(holds.scratch) > 1 {
		p.extra = slices.Clone(holds.scratch[1:])
	}
	clear(holds.scratch)
	holds.scratch = holds.scratch[:0]
	holds.parked = append(holds.parked, p)

	for _, hold := range holds.manual {
		if keptBy&hold.bit != 0 {
			hold.count++
			if hold.count >= hold.limit {
				release |= hold.bit
			}
		}
	}
	if release != 0 {
		// The release queues what it lets go of behind the packets already pending, and the caller's next
		// flush sends them. A direct write's own batch goes out before the pending batch.
		conn.releaseHeldLocked(release)
	}
}

// releaseHeldLocked lets go of everything the holds in mask keep. Packets no hold keeps any more are
// queued, in the order they were written, behind the pending batch. It reports whether any were queued.
// The caller holds sendMu.
func (conn *Conn) releaseHeldLocked(mask uint64) bool {
	holds := &conn.holds
	for _, hold := range holds.manual {
		if mask&hold.bit != 0 {
			hold.count = 0
		}
	}
	// Once the connection is cancelled, nothing sends what is released any more: a writer that passed its
	// context check before an Abort releases it only for the drop, so it never joins the send order.
	cancelled := conn.ctx != nil && conn.ctx.Err() != nil
	queued, kept := 0, 0
	for _, p := range holds.parked {
		if p.keptBy &^= mask; p.keptBy != 0 {
			holds.parked[kept] = p
			kept++
			continue
		}
		conn.bufferedSend = append(conn.bufferedSend, p.data)
		conn.bufferedSend = append(conn.bufferedSend, p.extra...)
		if p.sent != nil {
			conn.bufferedObservers = append(conn.bufferedObservers, packetCompletion{after: len(conn.bufferedSend), sent: p.sent})
		}
		// The packet is queued now, so whatever is written next goes out behind it.
		if p.released != nil && !cancelled {
			p.released()
		}
		queued++
	}
	clear(holds.parked[kept:])
	holds.parked = holds.parked[:kept]
	return queued != 0
}
