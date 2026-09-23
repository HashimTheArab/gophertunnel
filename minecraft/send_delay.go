package minecraft

import (
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// SetSendDelay adds latency d to everything the Conn sends. Packets are encoded exactly as without a delay;
// only the encoded bytes wait d before they reach the network, in the order they were sent. A new d applies
// to what is sent afterwards and never reorders, so after lowering it new packets still wait for those held
// before them. A d of zero or less stops delaying and sends everything held immediately. Close sends what is
// held without waiting; Abort discards it.
func (conn *Conn) SetSendDelay(d time.Duration) {
	conn.delay.set(d)
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

	mu    sync.Mutex
	held  []heldWrite
	timer *time.Timer
	// err is the first error writing a held batch failed with, returned from every later Write.
	err error
}

// heldWrite is one encoded batch and the time it may be written.
type heldWrite struct {
	due  time.Time
	data []byte
}

// Write writes b to w now if nothing is held and no delay is set, and otherwise holds a copy of it.
func (d *delayWriter) Write(b []byte) (int, error) {
	delay := time.Duration(d.delay.Load())
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return 0, d.err
	}
	if len(d.held) == 0 && delay <= 0 {
		return d.w.Write(b)
	}
	d.held = append(d.held, heldWrite{due: time.Now().Add(delay), data: slices.Clone(b)})
	if len(d.held) == 1 {
		d.armLocked()
	}
	return len(b), nil
}

// set changes the delay, writing everything held when it is cleared.
func (d *delayWriter) set(delay time.Duration) {
	d.delay.Store(int64(max(delay, 0)))
	if delay <= 0 {
		d.release(true)
	}
}

// release writes the held batches that are due, or all of them when all is set, and arms the timer for
// the next one. The clock is read again after every write, so batches that fall due meanwhile go too.
func (d *delayWriter) release(all bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for ; n < len(d.held) && (all || !d.held[n].due.After(time.Now())); n++ {
		if d.err == nil {
			_, d.err = d.w.Write(d.held[n].data)
		}
	}
	d.held = slices.Delete(d.held, 0, n)
	if d.err != nil {
		d.held = nil
	}
	d.armLocked()
}

// drop discards everything held, for a Conn that will never send it.
func (d *delayWriter) drop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.held = nil
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
		d.timer = time.AfterFunc(wait, func() { d.release(false) })
		return
	}
	d.timer.Reset(wait)
}
