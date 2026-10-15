package minecraft

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"testing"
	"testing/synctest"
	"time"
	"unsafe"

	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

func TestIncomingBatchStatsOwnedStorage(t *testing.T) {
	for _, test := range []struct {
		name     string
		advance  int
		disjoint bool
	}{
		{name: "payload aliases full"},
		{name: "advanced interior payload", advance: 2},
		{name: "disjoint payload fallback", disjoint: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			borrowed := make([]byte, 5, 128)
			copy(borrowed, []byte{127, 1, 2, 3, 4})
			want := bytes.Clone(borrowed)
			payload := borrowed[1:]
			if test.disjoint {
				payload = bytes.Repeat([]byte{42}, 129)
			}
			data := &packetData{h: &packet.Header{PacketID: 127}, full: borrowed, payload: bytes.NewBuffer(payload)}
			data.payload.Next(test.advance)
			owned := data.ensureOwned()
			if owned.ensureOwned() != owned {
				t.Fatal("already-owned packet was cloned again")
			}
			wantBacking := uint64(cap(owned.full))
			if test.disjoint {
				wantBacking += uint64(owned.payload.Cap())
			}
			clear(borrowed)
			if !bytes.Equal(owned.full, want) {
				t.Fatal("owned full frame aliases borrowed input")
			}
			batch := make([]*packetData, 1, 16)
			batch[0] = owned
			queuedAt := time.Unix(100, 0)
			conn := &Conn{}
			conn.readBatches.push(newIncomingBatch(batch), queuedAt)
			stats := conn.IncomingBatchStats(queuedAt.Add(time.Second))
			wantMetadata := uint64(cap(batch))*uint64(unsafe.Sizeof(owned)) +
				uint64(unsafe.Sizeof(*owned)+unsafe.Sizeof(*owned.h)+unsafe.Sizeof(*owned.payload))
			if stats.Batches != 1 || stats.Packets != 1 || stats.PacketBytes != uint64(len(want)) ||
				stats.BackingBytes != wantBacking || stats.MetadataBytes != wantMetadata || stats.OldestAge != time.Second {
				t.Fatalf("owned storage snapshot = %+v, want backing %d metadata %d", stats, wantBacking, wantMetadata)
			}
			if stats.RetainedBytes() != wantBacking+wantMetadata+stats.QueueBytes {
				t.Fatal("retained storage double-counts logical frame bytes")
			}
			owned.payload.Next(owned.payload.Len())
			owned.payload.Reset()
			if got := conn.IncomingBatchStats(queuedAt.Add(time.Second)); got != stats {
				t.Fatalf("payload cursor changed a queued charge: %+v -> %+v", stats, got)
			}
			if popped, ok := conn.readBatches.pop(); !ok || popped[0] != owned {
				t.Fatal("pop changed the batch owner")
			}
			assertIncomingQueueEmpty(t, conn.IncomingBatchStats(queuedAt))
			// Re-publishing after cursor mutation must recover the original allocation charge.
			conn.readBatches.push(newIncomingBatch(batch), queuedAt)
			if got := conn.IncomingBatchStats(queuedAt).BackingBytes; got != wantBacking {
				t.Fatalf("re-published backing = %d, want %d", got, wantBacking)
			}
			if !bytes.Equal(owned.full, want) {
				t.Fatal("dequeue or cursor mutation changed caller-owned raw bytes")
			}
		})
	}
}

func TestIncomingBatchQueueReclaimsPartialDrain(t *testing.T) {
	var queue incomingBatchQueue
	var want []*packetData
	start := time.Unix(100, 0)
	appendBatch := func(index int) {
		data := incomingQueuePacket(t, []byte{byte(index >> 8), byte(index)})
		want = append(want, data)
		queue.push(newIncomingBatch([]*packetData{data}), start.Add(time.Duration(index)*time.Second))
	}
	const burst = 512
	for index := range burst {
		appendBatch(index)
	}
	read := 0
	pop := func() {
		old := queue.entries
		batch, ok := queue.pop()
		if !ok || len(batch) != 1 || batch[0] != want[read] {
			t.Fatalf("batch %d lost FIFO order", read)
		}
		read++
		if unsafe.SliceData(old) != unsafe.SliceData(queue.entries) {
			assertIncomingRingCleared(t, old)
		}
	}
	for range burst / 4 {
		pop()
	}
	for index := burst; index < burst+burst/4; index++ {
		appendBatch(index)
	}
	// The live FIFO now wraps. Keep it nonempty throughout reclamation.
	for queue.length > 1 {
		pop()
		stats := queue.snapshot(start.Add(1000 * time.Second))
		if stats.Batches != len(want)-read || stats.Packets != stats.Batches ||
			len(queue.entries) > max(batchQueueRetainedCapacity, 4*queue.length) {
			t.Fatalf("partially drained queue retains its historical burst: %+v, slots %d", stats, len(queue.entries))
		}
		var packetBytes, backingBytes uint64
		for _, data := range want[read:] {
			packetBytes += uint64(len(data.full))
			backingBytes += uint64(cap(data.full))
		}
		if stats.PacketBytes != packetBytes || stats.BackingBytes != backingBytes ||
			stats.OldestAge != time.Duration(1000-read)*time.Second {
			t.Fatalf("remaining ownership/oldest age = %+v, first remaining index %d", stats, read)
		}
	}
	if len(queue.entries) != batchQueueRetainedCapacity {
		t.Fatal("one remaining batch still retains the burst ring")
	}
	pop()
	assertIncomingQueueEmpty(t, queue.snapshot(start))
	assertIncomingRingCleared(t, queue.entries)
	if _, ok := queue.pop(); ok {
		t.Fatal("empty queue returned another batch")
	}
}

func TestIncomingBatchQueueAmortizedRingWork(t *testing.T) {
	var queue incomingBatchQueue
	batch := func() incomingBatch {
		data := incomingQueuePacket(t, []byte{1})
		return newIncomingBatch([]*packetData{data})
	}
	var operations, resizeWork int
	observe := func(old []incomingBatch) {
		operations++
		if unsafe.SliceData(old) != unsafe.SliceData(queue.entries) {
			// A replacement clears the old ring and copies only the live entries.
			resizeWork += len(old) + queue.length
			assertIncomingRingCleared(t, old)
		}
	}
	for range 4 {
		for range 1024 {
			old := queue.entries
			queue.push(batch(), time.Unix(100, 0))
			observe(old)
		}
		for queue.length > 1 {
			old := queue.entries
			queue.pop()
			observe(old)
		}
	}
	if resizeWork > 8*operations+batchQueueRetainedCapacity {
		t.Fatalf("ring replacement work %d grows faster than %d queue operations", resizeWork, operations)
	}
	// A continuously occupied ring must not oscillate between growth and shrink.
	for range 16 {
		queue.push(batch(), time.Unix(100, 0))
	}
	old := unsafe.SliceData(queue.entries)
	for range 1024 {
		queue.pop()
		queue.push(batch(), time.Unix(100, 0))
		if unsafe.SliceData(queue.entries) != old {
			t.Fatal("steady dequeue/enqueue repeatedly relocates the live backlog")
		}
	}
}

func TestIncomingBatchStatsCallerTime(t *testing.T) {
	var queue incomingBatchQueue
	first := time.Unix(100, 0)
	data := incomingQueuePacket(t, nil)
	queue.push(newIncomingBatch([]*packetData{data}), first)
	queue.push(newIncomingBatch([]*packetData{incomingQueuePacket(t, nil)}), first.Add(time.Second))
	if age := queue.snapshot(first.Add(-time.Second)).OldestAge; age != 0 {
		t.Fatalf("age before enqueue = %v", age)
	}
	if age := queue.snapshot(first.Add(3 * time.Second)).OldestAge; age != 3*time.Second {
		t.Fatalf("oldest age = %v", age)
	}
	queue.pop()
	if age := queue.snapshot(first.Add(3 * time.Second)).OldestAge; age != 2*time.Second {
		t.Fatalf("age did not advance with FIFO head: %v", age)
	}
	queue.pop()
	assertIncomingQueueEmpty(t, queue.snapshot(first.Add(3*time.Second)))
}

func TestIncomingBatchQueueLevelWakeups(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := incomingQueueConn(t)
		frames := make(chan []byte, 3)
		go func() {
			defer close(frames)
			for range 3 {
				batch, err := conn.ReadBatchRaw(nil)
				if err != nil {
					t.Error(err)
					return
				}
				if len(batch) != 1 {
					t.Errorf("batch length = %d, want 1", len(batch))
					return
				}
				frames <- batch[0].Data
			}
		}()
		synctest.Wait()
		var want [][]byte
		for index := range 3 {
			data := incomingQueuePacket(t, []byte{byte(index)})
			want = append(want, data.full)
			conn.deferPacket(data)
			conn.flushBatch()
		}
		synctest.Wait()
		for index, frame := range want {
			select {
			case got, ok := <-frames:
				if !ok || !bytes.Equal(got, frame) {
					t.Fatalf("woken batch %d = %x, want %x", index, got, frame)
				}
			default:
				t.Fatal("coalesced readiness stranded a complete batch")
			}
		}
		assertIncomingQueueEmpty(t, conn.IncomingBatchStats(time.Unix(100, 0)))
	})
}

func TestIncomingBatchStatsConcurrentPublication(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := incomingQueueConn(t)
		data := incomingQueuePacket(t, []byte{1, 2, 3})
		const count = 512
		published, drained := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(published)
			for range count {
				if err := conn.receive(data.full); err != nil {
					t.Error(err)
					return
				}
				conn.flushBatch()
			}
		}()
		go func() {
			defer close(drained)
			for range count {
				batch, err := conn.ReadBatchRaw(nil)
				if err != nil || len(batch) != 1 || !bytes.Equal(batch[0].Data, data.full) {
					t.Errorf("concurrent batch = %v, %v", batch, err)
					return
				}
			}
		}()
		for range count {
			stats := conn.IncomingBatchStats(time.Unix(100, 0))
			if stats.Packets != stats.Batches || stats.PacketBytes != uint64(stats.Packets*len(data.full)) ||
				stats.BackingBytes != uint64(stats.Packets)*uint64(cap(data.full)) {
				t.Fatalf("incoherent concurrent snapshot: %+v", stats)
			}
		}
		<-published
		<-drained
		assertIncomingQueueEmpty(t, conn.IncomingBatchStats(time.Unix(100, 0)))
	})
}

func TestIncomingBatchStatsDrainBeforeTerminal(t *testing.T) {
	for _, terminal := range []string{"abort", "deadline", "disconnect", "deferred after abort"} {
		t.Run(terminal, func(t *testing.T) {
			conn := incomingQueueConn(t)
			first, second := incomingQueuePacket(t, []byte{1}), incomingQueuePacket(t, []byte{2})
			conn.deferPacket(first)
			conn.collectPacket(second)
			assertIncomingQueueEmpty(t, conn.IncomingBatchStats(time.Unix(100, 0)))
			switch terminal {
			case "abort":
				conn.flushBatch()
				_ = conn.Abort()
			case "deadline":
				conn.flushBatch()
				deadline := make(chan time.Time)
				conn.readDeadline = deadline
				close(deadline)
			case "disconnect":
				frame := incomingQueueFrame(t, &packet.Disconnect{Reason: packet.DisconnectReasonServerFull, Message: "fixture closed"})
				if err := conn.receive(frame); err != nil {
					t.Fatal(err)
				}
			case "deferred after abort":
				_ = conn.Abort()
				conn.flushBatch()
			}
			if stats := conn.IncomingBatchStats(time.Unix(100, 0)); stats.Batches != 1 || stats.Packets != 2 {
				t.Fatalf("terminal lost the accepted prefix: %+v", stats)
			}
			batch, err := conn.ReadBatchRaw(nil)
			if err != nil || len(batch) != 2 || !bytes.Equal(batch[0].Data, first.full) || !bytes.Equal(batch[1].Data, second.full) {
				t.Fatalf("prefix order/bytes = %v, %v", batch, err)
			}
			assertIncomingQueueEmpty(t, conn.IncomingBatchStats(time.Unix(100, 0)))
			_, err = conn.ReadBatchRaw(nil)
			switch terminal {
			case "disconnect":
				var disconnect *DisconnectPacketError
				if !errors.As(err, &disconnect) || disconnect.Reason != packet.DisconnectReasonServerFull || disconnect.Message != "fixture closed" {
					t.Fatalf("disconnect cause = %v", err)
				}
			case "deadline":
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("deadline error = %v", err)
				}
			default:
				if !errors.Is(err, net.ErrClosed) {
					t.Fatalf("abort error = %v", err)
				}
			}
			if conn.ctx.Err() != nil {
				conn.collectPacket(incomingQueuePacket(t, []byte{3}))
				conn.flushBatch()
				assertIncomingQueueEmpty(t, conn.IncomingBatchStats(time.Unix(100, 0)))
			}
		})
	}
}

func TestIncomingBatchStatsSelectiveDecode(t *testing.T) {
	for _, test := range []struct {
		name          string
		selectText    bool
		invalidCloses bool
		want          []int
	}{
		{name: "raw", want: []int{0, 1, 2, 3}},
		{name: "skip invalid selected", selectText: true, want: []int{0, 2, 3}},
		{name: "stop on closing decode", selectText: true, invalidCloses: true, want: []int{0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn := incomingQueueConn(t)
			conn.disconnectOnInvalidPacket = test.invalidCloses
			text := incomingQueueFrame(t, &packet.Text{TextType: packet.TextTypeRaw, Message: "fixture"})
			frames := [][]byte{
				incomingQueuePacket(t, []byte{1}).full,
				append(bytes.Clone(text), 0xff),
				text,
				incomingQueuePacket(t, []byte{2}).full,
			}
			for _, frame := range frames {
				if err := conn.receive(frame); err != nil {
					t.Fatal(err)
				}
			}
			conn.flushBatch()
			if stats := conn.IncomingBatchStats(time.Unix(100, 0)); stats.Packets != len(frames) {
				t.Fatalf("selected packets lost their raw storage charge: %+v", stats)
			}
			var decode func(uint32) bool
			if test.selectText {
				decode = func(id uint32) bool { return id == packet.IDText }
			}
			batch, err := conn.ReadBatchRaw(decode)
			if err != nil || len(batch) != len(test.want) {
				t.Fatalf("selected batch length = %d, %v", len(batch), err)
			}
			for index, source := range test.want {
				if !bytes.Equal(batch[index].Data, frames[source]) ||
					(len(batch[index].Decoded) != 0) != (test.selectText && source == 2) {
					t.Fatalf("selected packet %d changed bytes or decode selection", index)
				}
			}
			assertIncomingQueueEmpty(t, conn.IncomingBatchStats(time.Unix(100, 0)))
			if test.invalidCloses && conn.ctx.Err() == nil {
				t.Fatal("closing decode error did not cancel the connection")
			}
		})
	}
}

func TestIncomingBatchStatsLegalDecodedBatches(t *testing.T) {
	const limit = 4096
	for _, manySmall := range []bool{false, true} {
		name := "one large frame"
		if manySmall {
			name = "many minimum raw frames"
		}
		t.Run(name, func(t *testing.T) {
			conn := incomingQueueConn(t)
			var frames [][]byte
			if manySmall {
				frame := incomingQueueFrame(t, &packet.Unknown{PacketID: 127})
				for range limit / 2 {
					frames = append(frames, frame)
				}
			} else {
				frames = [][]byte{incomingQueueFrame(t, &packet.Unknown{PacketID: 127, Payload: bytes.Repeat([]byte{42}, limit-8)})}
			}
			wire := incomingQueueWire(t, frames)
			decoder := packet.NewDecoder(bytes.NewReader(wire))
			decoder.EnableCompression(packet.NopCompression, limit)
			decoder.DisableBatchPacketLimit()
			if err := decoder.DecodeFunc(func(frame []byte) error {
				err := conn.receive(frame)
				clear(frame)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			conn.flushBatch()
			stats := conn.IncomingBatchStats(time.Unix(100, 0))
			if stats.Batches != 1 || stats.Packets != len(frames) || stats.RetainedBytes() <= stats.PacketBytes {
				t.Fatalf("legal batch storage/boundary = %+v", stats)
			}
			batch, err := conn.ReadBatchRaw(nil)
			if err != nil || len(batch) != len(frames) {
				t.Fatalf("legal batch = %d packets, %v", len(batch), err)
			}
			for index, frame := range frames {
				if !bytes.Equal(batch[index].Data, frame) {
					t.Fatalf("borrowed decoder storage corrupted raw packet %d", index)
				}
			}
			assertIncomingQueueEmpty(t, conn.IncomingBatchStats(time.Unix(100, 0)))
		})
	}
}

func TestIncomingBatchStatsMalformedFraming(t *testing.T) {
	conn := incomingQueueConn(t)
	frame := incomingQueuePacket(t, []byte{1, 2, 3}).full
	wire := incomingQueueWire(t, [][]byte{frame, frame})
	decoder := packet.NewDecoder(bytes.NewReader(wire[:len(wire)-1]))
	decoder.EnableCompression(packet.NopCompression, 4096)
	callbacks := 0
	err := decoder.DecodeFunc(func(frame []byte) error {
		callbacks++
		return conn.receive(frame)
	})
	conn.flushBatch()
	if err == nil || callbacks != 0 {
		t.Fatalf("malformed framing dispatched %d packets, error %v", callbacks, err)
	}
	assertIncomingQueueEmpty(t, conn.IncomingBatchStats(time.Unix(100, 0)))
}

func TestIncomingBatchStatsExcludeSinglePacketDeferral(t *testing.T) {
	conn := incomingQueueConn(t)
	conn.batchReading = false
	data := incomingQueuePacket(t, []byte{1, 2, 3})
	conn.deferPacket(data)
	assertIncomingQueueEmpty(t, conn.IncomingBatchStats(time.Unix(100, 0)))
	got, ok := conn.takeDeferredPacket()
	if !ok || !bytes.Equal(got.full, data.full) {
		t.Fatal("single-packet deferral changed raw bytes")
	}
}

// incomingQueueConn creates a batch-reading dialer-side connection without network services.
func incomingQueueConn(t *testing.T) *Conn {
	t.Helper()
	client, peer := net.Pipe()
	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	conn.pool = conn.proto.Packets(false)
	conn.batchReading, conn.loggedIn = true, true
	t.Cleanup(func() {
		_ = conn.Abort()
		_ = peer.Close()
	})
	return conn
}

// incomingQueueFrame encodes an original packet fixture with the shared protocol encoder.
func incomingQueueFrame(t *testing.T, value packet.Packet) []byte {
	t.Helper()
	frame, err := encodePacket(value)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

// incomingQueuePacket returns a distinct, owned raw frame with the supplied fixture payload.
func incomingQueuePacket(t *testing.T, payload []byte) *packetData {
	t.Helper()
	frame := incomingQueueFrame(t, &packet.Unknown{PacketID: 777, Payload: payload})
	data, err := parseData(frame, &Conn{})
	if err != nil {
		t.Fatal(err)
	}
	return data.ensureOwned()
}

// incomingQueueWire builds one uncompressed wire batch, including batches beyond the encoder's split count.
func incomingQueueWire(t *testing.T, frames [][]byte) []byte {
	t.Helper()
	var wire bytes.Buffer
	encoder := packet.NewEncoder(&wire)
	encoder.EnableCompression(packet.NopCompression, 1)
	if err := encoder.Encode(nil); err != nil {
		t.Fatal(err)
	}
	for _, frame := range frames {
		if err := protocol.WriteVaruint32(&wire, uint32(len(frame))); err != nil {
			t.Fatal(err)
		}
		_, _ = wire.Write(frame)
	}
	return wire.Bytes()
}

// assertIncomingQueueEmpty permits retained ring storage but no charges for transferred batches.
func assertIncomingQueueEmpty(t *testing.T, stats IncomingBatchStats) {
	t.Helper()
	if stats.Batches != 0 || stats.Packets != 0 || stats.PacketBytes != 0 || stats.BackingBytes != 0 ||
		stats.MetadataBytes != 0 || stats.OldestAge != 0 || stats.RetainedBytes() != stats.QueueBytes {
		t.Fatalf("empty queue retains batch ownership: %+v", stats)
	}
}

// assertIncomingRingCleared verifies that old or drained ring storage cannot retain any batch owner.
func assertIncomingRingCleared(t *testing.T, entries []incomingBatch) {
	t.Helper()
	for index, entry := range entries {
		if entry.packets != nil {
			t.Fatalf("unused ring retains a batch in slot %d", index)
		}
	}
}
