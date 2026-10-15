package minecraft

import (
	"time"
	"unsafe"
)

const batchQueueRetainedCapacity = 8

// IncomingBatchStats describes complete batches waiting for ReadBatch or ReadBatchRaw.
// It excludes producer-owned pending/deferred batches, decoder and transport buffers,
// returned batches, decoded output, channels and the Conn itself. Storage counts use
// slice capacities and Go type sizes, without allocator overhead or rounding of structs.
// They describe queue ownership, not process heap usage or RSS, and impose no byte limit.
type IncomingBatchStats struct {
	Batches int
	Packets int
	// PacketBytes is the logical length of the queued encoded frames, including packet headers.
	PacketBytes uint64
	// BackingBytes counts distinct owned frame and disjoint payload byte-array capacities.
	// A payload view of a frame is not counted a second time.
	BackingBytes uint64
	// MetadataBytes counts packet/header/buffer records and batch pointer-array capacities.
	MetadataBytes uint64
	// QueueBytes is the current outer ring allocation, including its entry bookkeeping.
	// A resize temporarily holds both old and new rings; unreachable old storage awaits GC.
	QueueBytes uint64
	// OldestAge is the time since the oldest queued batch was enqueued, measured against now.
	// It is zero for an empty queue or when now precedes that enqueue time.
	OldestAge time.Duration
}

// RetainedBytes sums owned backing and metadata storage, without adding logical PacketBytes again.
func (stats IncomingBatchStats) RetainedBytes() uint64 {
	return stats.BackingBytes + stats.MetadataBytes + stats.QueueBytes
}

// IncomingBatchStats returns an O(1) snapshot of the complete incoming batch queue.
// The caller supplies now for age calculation. Enqueue time is recorded at the network edge.
// Dequeue transfers storage out of this queue even while the caller still retains it.
// Single-packet reading does not use this queue.
func (conn *Conn) IncomingBatchStats(now time.Time) IncomingBatchStats {
	conn.readQueueMu.Lock()
	defer conn.readQueueMu.Unlock()
	return conn.readBatches.snapshot(now)
}

// incomingBatch holds an immutable ownership charge alongside one complete batch.
type incomingBatch struct {
	packets       []*packetData
	queuedAt      time.Time
	packetBytes   uint64
	backingBytes  uint64
	metadataBytes uint64
}

// newIncomingBatch records the storage transferred by the producer. The batch owns its
// pointer array from its beginning, and each packet has passed ensureOwned. Packet records
// are distinct; only a packet's payload may alias its full frame. The producer must not
// mutate the batch after publishing it. Charging happens before taking the queue lock.
func newIncomingBatch(packets []*packetData) incomingBatch {
	batch := incomingBatch{
		packets:       packets,
		metadataBytes: uint64(cap(packets)) * uint64(unsafe.Sizeof((*packetData)(nil))),
	}
	for _, data := range packets {
		batch.packetBytes += uint64(len(data.full))
		batch.backingBytes += data.ownedCapacity
		batch.metadataBytes += uint64(unsafe.Sizeof(*data))
		if data.h != nil {
			batch.metadataBytes += uint64(unsafe.Sizeof(*data.h))
		}
		if data.payload != nil {
			batch.metadataBytes += uint64(unsafe.Sizeof(*data.payload))
		}
	}
	return batch
}

// incomingBatchQueue is a FIFO owned under Conn.readQueueMu. Push and pop have
// amortized constant ring work; charging a new batch is linear in its packet count.
type incomingBatchQueue struct {
	entries       []incomingBatch
	head, length  int
	packets       int
	packetBytes   uint64
	backingBytes  uint64
	metadataBytes uint64
}

// push publishes one charged batch at now without waiting for a reader or changing its boundary.
func (queue *incomingBatchQueue) push(batch incomingBatch, now time.Time) {
	if queue.length == len(queue.entries) {
		queue.resize(max(len(queue.entries)*2, batchQueueRetainedCapacity))
	}
	tail := (queue.head + queue.length) % len(queue.entries)
	batch.queuedAt = now
	queue.entries[tail] = batch
	queue.length++
	queue.packets += len(batch.packets)
	queue.packetBytes += batch.packetBytes
	queue.backingBytes += batch.backingBytes
	queue.metadataBytes += batch.metadataBytes
}

// pop transfers the oldest batch and its storage out of the queue. A quarter-full
// ring shrinks by half, leaving hysteresis before the next growth or shrink.
func (queue *incomingBatchQueue) pop() ([]*packetData, bool) {
	if queue.length == 0 {
		return nil, false
	}
	batch := queue.entries[queue.head]
	queue.entries[queue.head] = incomingBatch{}
	queue.head = (queue.head + 1) % len(queue.entries)
	queue.length--
	queue.packets -= len(batch.packets)
	queue.packetBytes -= batch.packetBytes
	queue.backingBytes -= batch.backingBytes
	queue.metadataBytes -= batch.metadataBytes
	if queue.length == 0 {
		queue.head = 0
		if len(queue.entries) > batchQueueRetainedCapacity {
			queue.resize(batchQueueRetainedCapacity)
		}
	} else if len(queue.entries) > batchQueueRetainedCapacity && queue.length <= len(queue.entries)/4 {
		queue.resize(max(len(queue.entries)/2, batchQueueRetainedCapacity))
	}
	return batch.packets, true
}

// resize copies the live FIFO in order and clears references from the old ring.
// Both allocations coexist during the copy; snapshots report only the current ring.
func (queue *incomingBatchQueue) resize(capacity int) {
	entries := make([]incomingBatch, capacity)
	first := min(queue.length, len(queue.entries)-queue.head)
	copy(entries, queue.entries[queue.head:queue.head+first])
	copy(entries[first:], queue.entries[:queue.length-first])
	clear(queue.entries)
	queue.entries = entries
	queue.head = 0
}

// snapshot reports stored charges without walking or retaining queued packet data.
func (queue *incomingBatchQueue) snapshot(now time.Time) IncomingBatchStats {
	stats := IncomingBatchStats{
		Batches:       queue.length,
		Packets:       queue.packets,
		PacketBytes:   queue.packetBytes,
		BackingBytes:  queue.backingBytes,
		MetadataBytes: queue.metadataBytes,
		QueueBytes:    uint64(cap(queue.entries)) * uint64(unsafe.Sizeof(incomingBatch{})),
	}
	if queue.length != 0 {
		stats.OldestAge = max(0, now.Sub(queue.entries[queue.head].queuedAt))
	}
	return stats
}

// takeBatch transfers a complete network batch, draining the readiness signal only when empty.
func (conn *Conn) takeBatch() ([]*packetData, bool) {
	conn.readQueueMu.Lock()
	defer conn.readQueueMu.Unlock()
	batch, ok := conn.readBatches.pop()
	if ok && conn.readBatches.length == 0 {
		select {
		case <-conn.batchReady:
		default:
		}
	}
	return batch, ok
}

// queueBatch publishes a complete network batch without waiting for consumer capacity.
func (conn *Conn) queueBatch(packets []*packetData) {
	batch := newIncomingBatch(packets)
	conn.readQueueMu.Lock()
	conn.readBatches.push(batch, time.Now())
	select {
	case conn.batchReady <- struct{}{}:
	default:
	}
	conn.readQueueMu.Unlock()
}
