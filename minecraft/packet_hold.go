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

// errHoldInUse is returned by PacketHold.Set when another hold on the Conn already holds the same way.
var errHoldInUse = errors.New("minecraft: another packet hold on this connection already holds this way")

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

// limit is the number of packets a manual hold keeps before it lets go of all of them.
func (r PacketHoldRule) limit() int { return max(r.Limit, 1) }

// PacketHold holds packets written to the Conn that created it according to its rule. A Conn has at most
// one manual hold and one delay hold at a time. Packets the manual hold lets go of join the pending batch
// and then wait for the Delay like any other, counted from the flush that submits them. The WriteObserver
// completes a held packet once it reaches the transport. Close sends what is held and Abort drops it.
//
// A PacketHold is safe for concurrent use. A nil *PacketHold holds nothing, so a stand-in for a Conn that
// cannot hold packets can return one.
type PacketHold struct {
	conn *Conn
	rule PacketHoldRule // guarded by conn.sendMu
}

// NewPacketHold returns a hold on conn that holds nothing until its rule is set.
func (conn *Conn) NewPacketHold() *PacketHold {
	return &PacketHold{conn: conn}
}

// Set replaces the hold's rule. Packets the hold keeps stay held while the new rule is manual and under
// its limit, and are let go of otherwise. Packets let go of are queued behind the pending batch: Set never
// flushes, so its caller decides where the batch ends. A lower Delay applies to what is sent afterwards.
// It returns an error if another hold on the Conn already holds the same way, any failure sending delayed
// packets when the Delay changes, and net.ErrClosed once the Conn shuts down.
func (h *PacketHold) Set(rule PacketHoldRule) error {
	if h == nil {
		return nil
	}
	rule.Delay = max(rule.Delay, 0)
	if rule.Delay > 0 && (rule.manual() || rule.Limit != 0 || rule.SelectableOnly) {
		return errors.New("minecraft: a packet hold rule cannot both delay and select packets")
	}
	conn := h.conn
	// holdMu keeps the delay published below current until the rule is applied.
	conn.holdMu.Lock()
	defer conn.holdMu.Unlock()
	conn.sendMu.Lock()
	holds := &conn.holds
	if conn.closedLocked() {
		holds.close()
		conn.sendMu.Unlock()
		return net.ErrClosed
	}
	if rule.manual() && holds.manual != nil && holds.manual != h || rule.Delay > 0 && holds.delayed != nil && holds.delayed != h {
		conn.sendMu.Unlock()
		return errHoldInUse
	}
	oldDelay := h.rule.Delay
	conn.sendMu.Unlock()
	var err error
	if rule.Delay != oldDelay {
		// Published before the rule applies, so a racing Flush never submits what the rule lets go of under
		// the old delay. Publishing can write to the transport, so it runs without sendMu.
		err = conn.delay.set(rule.Delay)
	}

	conn.sendMu.Lock()
	defer conn.sendMu.Unlock()
	if conn.closedLocked() {
		holds.close()
		return errors.Join(err, net.ErrClosed)
	}
	wasManual := holds.manual == h
	h.rule = rule
	holds.manual = claim(holds.manual, h, rule.manual())
	holds.delayed = claim(holds.delayed, h, rule.Delay > 0)
	if wasManual && (!rule.manual() || len(holds.parked) >= rule.limit()) {
		conn.releaseHeldLocked()
	}
	return err
}

// claim returns who holds a slot owned by owner once h does, or does not, use it.
func claim(owner, h *PacketHold, uses bool) *PacketHold {
	if uses {
		return h
	}
	if owner == h {
		return nil
	}
	return owner
}

// Release lets go of everything the hold keeps and keeps holding, like PacketHoldRelease. The packets it
// lets go of are queued behind the pending batch: Release never flushes, so its caller decides where the
// batch ends. It returns net.ErrClosed once the Conn shuts down.
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
	if conn.holds.manual == h {
		conn.releaseHeldLocked()
	}
	return nil
}

// Discard drops everything the hold keeps without sending it, and keeps holding. Discarded packets never
// complete and never join the send order.
func (h *PacketHold) Discard() {
	if h == nil {
		return
	}
	conn := h.conn
	conn.sendMu.Lock()
	defer conn.sendMu.Unlock()
	if conn.holds.manual == h {
		clear(conn.holds.parked)
		conn.holds.parked = conn.holds.parked[:0]
	}
}

// packetHolds is a Conn's holds and the packets its manual hold keeps. The connection's sendMu guards it.
type packetHolds struct {
	manual  *PacketHold    // the hold with a manual rule, if any
	delayed *PacketHold    // the hold with a Delay, if any
	parked  []parkedPacket // packets the manual hold keeps, in write order
	scratch [][]byte       // wire packets of the logical packet being held
	closed  bool           // set once the Conn shuts down; a closed Conn holds nothing
}

// parkedPacket is one held logical packet: its wire packets, WriteObserver completion and QueueObserver
// release.
type parkedPacket struct {
	data     []byte
	extra    [][]byte
	sent     func()
	released func()
}

// closedLocked reports whether the Conn has shut down, so its holds hold nothing. The caller holds sendMu.
func (conn *Conn) closedLocked() bool {
	return conn.ctx == nil || conn.ctx.Err() != nil || conn.holds.closed
}

// close drops everything held and refuses later holds.
func (h *packetHolds) close() {
	clear(h.parked)
	clear(h.scratch)
	*h = packetHolds{closed: true}
}

// dropHeld discards held packets for Abort, together with the pending batch, which no flush sends once
// the connection is cancelled. Abort must never wait, even when its own caller holds sendMu, so if sendMu
// is busy, a goroutine drops them as soon as the holder lets go.
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

// closeHold queues everything held for Close's final flush and stops holding, so a Set racing the rest of
// Close gets net.ErrClosed. A connection already cancelled drops what it holds.
func (conn *Conn) closeHold() {
	conn.sendMu.Lock()
	defer conn.sendMu.Unlock()
	conn.releaseHeldLocked()
	conn.holds.close()
}

// selectLocked returns what the manual hold, if any, does with pk. The caller holds sendMu.
func (conn *Conn) selectLocked(pk packet.Packet, selectable bool) PacketHoldDecision {
	hold := conn.holds.manual
	if hold == nil || hold.rule.SelectableOnly && !selectable {
		return PacketHoldSend
	}
	return hold.rule.Select(pk)
}

// parkLocked keeps pk, whose wire packets are in holds.scratch, runs its captures, and lets go of
// everything held once the hold reaches its limit. The caller holds sendMu.
func (conn *Conn) parkLocked(pk packet.Packet) {
	holds := &conn.holds
	p := parkedPacket{data: holds.scratch[0]}
	if len(holds.scratch) > 1 {
		p.extra = slices.Clone(holds.scratch[1:])
	}
	if conn.writeObserver != nil {
		p.sent = conn.writeObserver(pk)
	}
	if conn.queueObserver != nil {
		p.released = conn.queueObserver(pk, true)
	}
	holds.parked = append(holds.parked, p)
	if len(holds.parked) >= holds.manual.rule.limit() {
		// Queued behind the pending batch; a direct write's own batch goes out first.
		conn.releaseHeldLocked()
	}
}

// releaseHeldLocked queues everything held behind the pending batch, in write order, then runs their
// QueueObserver release functions. Once the connection is cancelled it releases nothing, so a writer that
// passed its context check before an Abort leaves held packets for the Abort to drop. The caller holds
// sendMu.
func (conn *Conn) releaseHeldLocked() {
	if conn.ctx != nil && conn.ctx.Err() != nil {
		return
	}
	parked := conn.holds.parked
	for _, p := range parked {
		conn.bufferedSend = append(conn.bufferedSend, p.data)
		conn.bufferedSend = append(conn.bufferedSend, p.extra...)
		if p.sent != nil {
			conn.bufferedObservers = append(conn.bufferedObservers, packetCompletion{after: len(conn.bufferedSend), sent: p.sent})
		}
	}
	for _, p := range parked {
		if p.released != nil {
			p.released()
		}
	}
	clear(parked)
	conn.holds.parked = parked[:0]
}
