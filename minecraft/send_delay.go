package minecraft

import (
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// SetSendDelay adds latency d to everything the Conn sends. Packets are encoded exactly as without a delay;
// only the encoded bytes wait d before they reach the network, in the order they were sent. A new d applies
// to what is sent afterwards and never reorders, so after lowering it new packets still wait for those held
// before them. A d of zero or less stops delaying and sends everything held immediately. Close sends what is
// held without waiting; Abort discards it. It returns any failure while releasing held batches, including
// an earlier send failure. The delay setting is applied even when a failure is returned.
func (conn *Conn) SetSendDelay(d time.Duration) error {
	return conn.delay.set(d)
}

// SendDelay returns the latency SetSendDelay last added to everything the Conn sends.
func (conn *Conn) SendDelay() time.Duration {
	return time.Duration(conn.delay.delay.Load())
}

// delayWriter sits between the packet encoder and the network, holding each encoded batch for the send
// delay before writing it to w.
type delayWriter struct {
	w     io.Writer
	delay atomic.Int64
	// aborted rejects new writes and completions without waiting for a blocked transport write.
	aborted atomic.Bool

	// mu serializes transport writes, completions and access to pending batches.
	mu             sync.Mutex
	held           []heldWrite
	nextObservers  []packetCompletion
	encodedPackets int
	timer          *time.Timer
	// err is the first send failure or net.ErrClosed after drop, returned from every later write.
	err error
}

// packetCompletion ties one logical packet to its last wire packet in the current encoder submission.
// Protocol conversion can expand a logical packet across transport batches, so only the last completes it.
type packetCompletion struct {
	after int
	sent  func()
}

// heldWrite is one encoded batch and the time it may be written.
type heldWrite struct {
	due       time.Time
	data      []byte
	observers []packetCompletion
}

// setObservers associates one encoder submission, which may produce several batches, with its callbacks.
// The connection's encoder lock serializes this with encoding and clearing on failure.
func (d *delayWriter) setObservers(observers []packetCompletion) {
	d.mu.Lock()
	if d.err != nil || d.aborted.Load() {
		observers = nil
	}
	d.nextObservers = observers
	d.encodedPackets = 0
	d.unlock()
}

// writeBatch sends b now if nothing is held and no delay is set, and otherwise holds a copy. packetCount
// selects only the logical packet completions whose final wire packet belongs to this actual batch.
func (d *delayWriter) writeBatch(b []byte, packetCount int) (int, error) {
	d.mu.Lock()
	defer d.unlock()
	if d.aborted.Load() {
		return 0, net.ErrClosed
	}
	if d.err != nil {
		return 0, d.err
	}
	d.encodedPackets += packetCount
	n := 0
	for n < len(d.nextObservers) && d.nextObservers[n].after <= d.encodedPackets {
		n++
	}
	observers := d.nextObservers[:n:n]
	d.nextObservers = d.nextObservers[n:]
	delay := time.Duration(d.delay.Load())
	if len(d.held) == 0 && delay <= 0 {
		return d.writeLocked(b, observers)
	}
	d.held = append(d.held, heldWrite{due: time.Now().Add(delay), data: slices.Clone(b), observers: observers})
	if len(d.held) == 1 {
		d.armLocked()
	}
	return len(b), nil
}

// writeLocked writes a complete batch and runs its completions only after the transport accepts all
// bytes. A failure is terminal because the encoder may already have advanced its encryption state.
// The caller holds mu, keeping transport writes and completion order serialized.
func (d *delayWriter) writeLocked(data []byte, observers []packetCompletion) (n int, err error) {
	defer func() {
		clear(observers)
		if err != nil {
			d.err = err
		}
	}()
	if d.aborted.Load() {
		return 0, net.ErrClosed
	}
	n, err = d.w.Write(data)
	if d.aborted.Load() {
		err = net.ErrClosed
	}
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		for _, observe := range observers {
			if d.aborted.Load() {
				err = net.ErrClosed
				break
			}
			observe.sent()
		}
	}
	return n, err
}

// set changes the delay under the same lock Write decides with, writing everything held when it is
// cleared. It returns the first send failure, if any.
func (d *delayWriter) set(delay time.Duration) error {
	d.mu.Lock()
	defer d.unlock()
	d.delay.Store(int64(max(delay, 0)))
	if d.aborted.Load() {
		d.dropLocked()
	}
	if delay > 0 {
		return d.err
	}
	return d.releaseLocked(true)
}

// releaseDue writes the held batches that are due. It runs when the timer fires.
func (d *delayWriter) releaseDue() {
	d.mu.Lock()
	defer d.unlock()
	_ = d.releaseLocked(false)
}

// failure returns the first send failure so an empty Flush still reports transport errors.
func (d *delayWriter) failure() error {
	d.mu.Lock()
	defer d.unlock()
	if d.err == nil && d.aborted.Load() {
		return net.ErrClosed
	}
	return d.err
}

// releaseLocked writes the held batches that are due, or all of them when all is set, and arms the timer
// for the next one. The clock is read again after every write, so batches that fall due meanwhile go too.
// It returns the first send failure, if any. The caller holds mu.
func (d *delayWriter) releaseLocked(all bool) error {
	if d.aborted.Load() {
		d.dropLocked()
		return d.err
	}
	n := 0
	for ; n < len(d.held) && (all || !d.held[n].due.After(time.Now())); n++ {
		if d.err == nil {
			_, _ = d.writeLocked(d.held[n].data, d.held[n].observers)
		}
	}
	d.held = slices.Delete(d.held, 0, n)
	if d.err != nil {
		d.held = nil
		d.nextObservers = nil
		d.encodedPackets = 0
	}
	d.armLocked()
	return d.err
}

// drop rejects later writes and completions immediately, including encodes already in flight. If a
// transport write holds mu, its unlock will discard the queued data without making Abort wait for it.
func (d *delayWriter) drop() {
	d.aborted.Store(true)
	if d.mu.TryLock() {
		d.dropLocked()
		d.mu.Unlock()
	}
}

// unlock releases the state lock before checking for abort. This order prevents a lost cleanup race:
// an earlier abort is seen here, and a later abort can take the free lock or rely on its next owner.
func (d *delayWriter) unlock() {
	d.mu.Unlock()
	if d.aborted.Load() {
		d.drop()
	}
}

// dropLocked clears all pending references and stops the delay timer. The caller holds mu.
func (d *delayWriter) dropLocked() {
	d.held = nil
	d.nextObservers = nil
	d.encodedPackets = 0
	if d.err == nil {
		d.err = net.ErrClosed
	}
	if d.timer != nil {
		d.timer.Stop()
	}
}

// armLocked schedules release for the oldest held batch, if any. The caller holds mu.
func (d *delayWriter) armLocked() {
	if len(d.held) == 0 {
		return
	}
	wait := time.Until(d.held[0].due)
	if d.timer == nil {
		d.timer = time.AfterFunc(wait, d.releaseDue)
		return
	}
	d.timer.Reset(wait)
}
