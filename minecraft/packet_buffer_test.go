package minecraft

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"runtime"
	"sync"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

func TestConnWritePacketSteadyStateAllocations(t *testing.T) {
	conn := newConn(packetBufferBenchmarkTransport{}, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	pk := &packet.PlayerAuthInput{}
	allocs := testing.AllocsPerRun(100, func() {
		if err := conn.WritePacket(pk); err != nil {
			t.Fatal(err)
		}
		if err := conn.Flush(); err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 6 {
		t.Fatalf("WritePacket plus Flush allocated %.0f times, want at most 6", allocs)
	}
}

func TestPacketWriterReuseRespectsCustomProtocolWriter(t *testing.T) {
	for _, test := range []struct {
		name    string
		adapted bool
	}{
		{name: "wrapped writer"},
		{name: "adapted concrete writer", adapted: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			custom := packetBufferCustomWriterProtocol{
				BasicProtocol:  BasicProtocol{Protocol: DefaultProtocol.ID(), Version: DefaultProtocol.Ver()},
				newWriterCalls: &calls,
				adapted:        test.adapted,
			}
			conn := newConn(packetBufferBenchmarkTransport{}, nil, slog.New(internal.DiscardHandler{}), custom, -1, false)
			if err := conn.WritePacket(&packet.PlayStatus{}); err != nil {
				t.Fatal(err)
			}
			if err := conn.WritePacket(&packet.PlayStatus{}); err != nil {
				t.Fatal(err)
			}
			if calls != 2 {
				t.Fatalf("custom Protocol.NewWriter called %d times, want 2", calls)
			}
		})
	}
}

func TestPacketWriterReusePreservesCustomShieldID(t *testing.T) {
	const remappedShieldID int32 = 99
	calls := 0
	custom := packetBufferCustomWriterProtocol{
		BasicProtocol:  BasicProtocol{Protocol: DefaultProtocol.ID(), Version: DefaultProtocol.Ver()},
		newWriterCalls: &calls,
		shieldID:       remappedShieldID,
	}
	conn := newConn(packetBufferBenchmarkTransport{}, nil, slog.New(internal.DiscardHandler{}), custom, -1, false)
	conn.shieldID.Store(7)
	var payloads [][]byte
	conn.packetFunc = func(_ packet.Header, payload []byte, _, _ net.Addr) {
		payloads = append(payloads, payload)
	}
	for range 2 {
		if err := conn.WritePacket(packetBufferShieldPacket{}); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatalf("custom Protocol.NewWriter called %d times, want 2", calls)
	}
	for i, payload := range payloads {
		var got int32
		protocol.NewReader(bytes.NewBuffer(payload), 0, false).Int32(&got)
		if got != remappedShieldID {
			t.Fatalf("packet %d shield ID = %d, want %d", i, got, remappedShieldID)
		}
	}
}

func TestPacketBufferReuseRequiresExactBuiltInProtocol(t *testing.T) {
	basic := BasicProtocol{Protocol: DefaultProtocol.ID(), Version: DefaultProtocol.Ver()}
	tests := []struct {
		name string
		p    Protocol
		want bool
	}{
		{name: "default", p: DefaultProtocol, want: true},
		{name: "basic", p: basic, want: true},
		{name: "legacy", p: Protocol12644(), want: true},
		{name: "pointer basic", p: &basic},
		{name: "custom writer", p: packetBufferCustomWriterProtocol{BasicProtocol: basic, newWriterCalls: new(int)}},
		{name: "custom reader", p: packetBufferZeroCopyReaderProtocol{BasicProtocol: basic}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := canReusePacketBuffers(test.p); got != test.want {
				t.Fatalf("canReusePacketBuffers = %v, want %v", got, test.want)
			}
		})
	}
}

func TestEnsureOwnedReusesPacketData(t *testing.T) {
	borrowed := []byte{1, 2, 3}
	data := &packetData{
		h:       &packet.Header{PacketID: 1},
		full:    borrowed,
		payload: bytes.NewBuffer(borrowed[1:]),
	}
	owned := data.ensureOwned()
	if owned != data {
		t.Fatal("ensureOwned allocated a replacement packetData")
	}
	clear(borrowed)
	if !bytes.Equal(owned.full, []byte{1, 2, 3}) || !bytes.Equal(owned.payload.Bytes(), []byte{2, 3}) {
		t.Fatalf("owned packet changed with decoder buffer: full=%v payload=%v", owned.full, owned.payload.Bytes())
	}
	raw := owned.takeFull()
	if cap(raw) != len(raw) {
		t.Fatalf("raw packet capacity = %d, want length %d", cap(raw), len(raw))
	}
}

func TestIncomingOwnedPacketSteadyStateAllocations(t *testing.T) {
	conn := &Conn{proto: DefaultProtocol, pool: DefaultProtocol.Packets(true)}
	frame := packetBufferFramesForTest(t, &packet.PlayStatus{})
	allocs := testing.AllocsPerRun(100, func() {
		data := packetBufferData(frame)
		if _, err := data.ensureOwned().decode(conn); err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 7 {
		t.Fatalf("owning and decoding one packet allocated %.0f times, want at most 7", allocs)
	}
}

func TestDecodedPacketDoesNotAliasReleasedOwnedBuffer(t *testing.T) {
	conn := &Conn{proto: DefaultProtocol, pool: DefaultProtocol.Packets(true)}
	frame := packetBufferFramesForTest(t, &packet.Unknown{PacketID: 700, Payload: []byte{1, 2, 3}})
	data := packetBufferData(frame).ensureOwned()
	decoded, err := data.decode(conn)
	if err != nil {
		t.Fatal(err)
	}
	reused := acquireOwnedPacketBuffer(len(frame))
	clear(reused)
	releaseOwnedPacketBuffer(reused)
	if got := decoded[0].(*packet.Unknown).Payload; !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatalf("decoded payload changed after owned buffer reuse: %v", got)
	}
}

func TestCustomZeroCopyReaderRetainsOwnedBuffer(t *testing.T) {
	custom := packetBufferZeroCopyReaderProtocol{
		BasicProtocol: BasicProtocol{Protocol: DefaultProtocol.ID(), Version: DefaultProtocol.Ver()},
	}
	conn := &Conn{proto: custom, pool: DefaultProtocol.Packets(true)}
	frame := packetBufferFramesForTest(t, &packet.Unknown{PacketID: 700, Payload: bytes.Repeat([]byte{7}, 20<<10)})
	held := drainOwnedPacketBufferClassForTest(len(frame))
	defer func() {
		for _, buffer := range held {
			releaseOwnedPacketBuffer(buffer)
		}
	}()

	decoded, err := packetBufferData(frame).ensureOwned().decode(conn)
	if err != nil {
		t.Fatal(err)
	}
	reused := acquireOwnedPacketBuffer(len(frame))
	clear(reused)
	releaseOwnedPacketBuffer(reused)
	if got := decoded[0].(*packet.Unknown).Payload; !bytes.Equal(got, bytes.Repeat([]byte{7}, 20<<10)) {
		t.Fatal("custom zero-copy reader payload changed after incoming pool reuse")
	}
}

func TestOutgoingPacketFuncPayloadIsOwned(t *testing.T) {
	conn := newConn(packetBufferBenchmarkTransport{}, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	payload := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	var captured, want []byte
	conn.packetFunc = func(_ packet.Header, got []byte, _, _ net.Addr) {
		if captured == nil {
			captured = got
			want = bytes.Clone(got)
		}
	}
	if err := conn.WritePacket(&packet.Unknown{PacketID: 700, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	clear(payload)
	for i := range 32 {
		if err := conn.WritePacket(&packet.Unknown{PacketID: 700, Payload: bytes.Repeat([]byte{byte(i + 1)}, len(payload))}); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(captured, want) {
		t.Fatalf("PacketFunc payload was reused after callback: got %x, want %x", captured, want)
	}
}

func TestWriteSnapshotsCallerBytes(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)

	frame := packetBufferFramesForTest(t, &packet.Unknown{PacketID: 700, Payload: []byte{1, 2, 3}})
	read := make(chan [][]byte, 1)
	go func() {
		packets, _ := packet.NewDecoder(server).Decode()
		read <- packets
	}()
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	clear(frame)
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	packets := <-read
	if len(packets) != 1 {
		t.Fatalf("decoded %d packets, want 1", len(packets))
	}
	data, err := parseData(packets[0], &Conn{})
	if err != nil {
		t.Fatal(err)
	}
	if got := data.payload.Bytes(); !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatalf("written payload changed with caller bytes: got %v", got)
	}
}

func TestWritePacketSnapshotsShapeSlice(t *testing.T) {
	conn := newConn(packetBufferBenchmarkTransport{}, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	shapes := []protocol.PrimitiveShape{{
		NetworkID:      42,
		ExtraShapeData: &protocol.LastShape{},
	}}
	var payload []byte
	conn.packetFunc = func(header packet.Header, got []byte, _, _ net.Addr) {
		if header.PacketID == packet.IDPrimitiveShapes {
			payload = bytes.Clone(got)
		}
	}
	if err := conn.WritePacket(&packet.PrimitiveShapes{Shapes: shapes}); err != nil {
		t.Fatal(err)
	}
	shapes[0].NetworkID = 99

	var decoded packet.PrimitiveShapes
	decoded.Marshal(protocol.NewReader(bytes.NewBuffer(payload), 0, false))
	if got := decoded.Shapes[0].NetworkID; got != 42 {
		t.Fatalf("encoded shape network ID = %d, want 42", got)
	}
}

func TestWritePacketCallerMutationDuringFlush(t *testing.T) {
	transport := &packetBufferRecordingTransport{}
	conn := newConn(transport, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	const packetCount = 64
	stopFlush := make(chan struct{})
	flushDone := make(chan struct{})
	go func() {
		defer close(flushDone)
		for {
			select {
			case <-stopFlush:
				return
			default:
				_ = conn.Flush()
				runtime.Gosched()
			}
		}
	}()

	var writers sync.WaitGroup
	for i := 1; i <= packetCount; i++ {
		writers.Add(1)
		go func(value byte) {
			defer writers.Done()
			payload := bytes.Repeat([]byte{value}, 4<<10)
			if err := conn.WritePacket(&packet.Unknown{PacketID: 700, Payload: payload}); err != nil {
				t.Error(err)
				return
			}
			clear(payload)
		}(byte(i))
	}
	writers.Wait()
	close(stopFlush)
	<-flushDone
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}

	seen := make(map[byte]int, packetCount)
	reader := &packetBufferBatchReader{batches: transport.snapshot()}
	decoder := packet.NewDecoder(reader)
	for range reader.remaining() {
		frames, err := decoder.Decode()
		if err != nil {
			t.Fatal(err)
		}
		for _, frame := range frames {
			data, err := parseData(frame, &Conn{})
			if err != nil {
				t.Fatal(err)
			}
			payload := data.payload.Bytes()
			if len(payload) == 0 || payload[0] == 0 {
				t.Fatalf("buffered packet observed mutated caller payload: %x", payload)
			}
			seen[payload[0]]++
		}
	}
	for i := 1; i <= packetCount; i++ {
		if seen[byte(i)] != 1 {
			t.Fatalf("payload %d observed %d times, want once", i, seen[byte(i)])
		}
	}
}

func TestWritePacketImmediatePreservesBufferedOrder(t *testing.T) {
	transport := &packetBufferRecordingTransport{}
	conn := newConn(transport, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	if err := conn.WritePacket(&packet.Unknown{PacketID: 700, Payload: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	if err := conn.WritePacketImmediate(&packet.Unknown{PacketID: 700, Payload: []byte{2}}); err != nil {
		t.Fatal(err)
	}
	got := packetBufferPayloadOrder(t, transport.snapshot())
	if !bytes.Equal(got, []byte{1, 2}) {
		t.Fatalf("immediate packet order = %v, want [1 2]", got)
	}
}

func TestWritePacketDirectBypassesBufferedQueue(t *testing.T) {
	transport := &packetBufferRecordingTransport{}
	conn := newConn(transport, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	if err := conn.WritePacket(&packet.Unknown{PacketID: 700, Payload: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	if err := conn.WritePacketDirect(&packet.Unknown{PacketID: 700, Payload: []byte{2}}); err != nil {
		t.Fatal(err)
	}
	if got := packetBufferPayloadOrder(t, transport.snapshot()); !bytes.Equal(got, []byte{2}) {
		t.Fatalf("direct write payloads = %v, want [2]", got)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := packetBufferPayloadOrder(t, transport.snapshot()); !bytes.Equal(got, []byte{2, 1}) {
		t.Fatalf("direct then buffered payloads = %v, want [2 1]", got)
	}
}

func TestPacketBufferPoolsDropOversizedStorage(t *testing.T) {
	oversized := acquireOwnedPacketBuffer(maxRetainedPacketBufferCap + 1)
	before := make([]int, len(ownedPacketBufferClasses))
	for i := range ownedPacketBufferClasses {
		class := &ownedPacketBufferClasses[i]
		class.mu.Lock()
		before[i] = len(class.buffers)
		class.mu.Unlock()
	}
	releaseOwnedPacketBuffer(oversized)
	for i := range ownedPacketBufferClasses {
		class := &ownedPacketBufferClasses[i]
		class.mu.Lock()
		got := len(class.buffers)
		class.mu.Unlock()
		if got != before[i] {
			t.Fatalf("oversized incoming buffer entered class %d: pool length %d, want %d", i, got, before[i])
		}
	}

	var queue packetQueue
	queue.buffer.Grow(maxRetainedPacketBufferCap + 1)
	queue.reset()
	if queue.buffer.Cap() != 0 {
		t.Fatalf("outgoing queue retained oversized capacity %d", queue.buffer.Cap())
	}
}

// packetBufferFramesForTest encodes one packet and returns its complete packet frame.
func packetBufferFramesForTest(t *testing.T, pk packet.Packet) []byte {
	t.Helper()
	conn := &Conn{proto: DefaultProtocol, hdr: &packet.Header{}}
	var queue packetQueue
	conn.encodePacketsTo(&queue, pk)
	if len(queue.packets) != 1 {
		t.Fatalf("encoded %d frames, want 1", len(queue.packets))
	}
	return queue.packets[0]
}

type packetBufferRecordingTransport struct {
	packetBufferBenchmarkTransport
	mu      sync.Mutex
	batches [][]byte
}

// Write records one immutable copy of a batch written by the encoder.
func (t *packetBufferRecordingTransport) Write(batch []byte) (int, error) {
	t.mu.Lock()
	t.batches = append(t.batches, bytes.Clone(batch))
	t.mu.Unlock()
	return len(batch), nil
}

// snapshot returns stable copies of all batches recorded so far.
func (t *packetBufferRecordingTransport) snapshot() [][]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([][]byte(nil), t.batches...)
}

type packetBufferBatchReader struct {
	batches [][]byte
	next    int
}

type packetBufferCustomWriterProtocol struct {
	BasicProtocol
	newWriterCalls *int
	adapted        bool
	shieldID       int32
}

// NewWriter records use of the custom protocol writer factory.
func (p packetBufferCustomWriterProtocol) NewWriter(dst ByteWriter, shieldID int32) protocol.IO {
	*p.newWriterCalls++
	if p.shieldID != 0 {
		return protocol.NewWriter(dst, p.shieldID)
	}
	if p.adapted {
		return protocol.NewWriter(packetBufferWriterAdapter{ByteWriter: dst}, shieldID)
	}
	return &packetBufferCustomWriter{IO: protocol.NewWriter(dst, shieldID)}
}

type packetBufferCustomWriter struct {
	protocol.IO
}

type packetBufferWriterAdapter struct {
	ByteWriter
}

type packetBufferShieldPacket struct{}

// ID returns a test-only unknown packet ID.
func (packetBufferShieldPacket) ID() uint32 { return 700 }

// Marshal writes the writer-specific shield ID into the test payload.
func (packetBufferShieldPacket) Marshal(io protocol.IO) {
	shieldID := io.ShieldID()
	io.Int32(&shieldID)
}

type packetBufferZeroCopyReaderProtocol struct {
	BasicProtocol
}

// NewReader returns a legal reader that aliases leftover bytes into decoded packets.
func (p packetBufferZeroCopyReaderProtocol) NewReader(src ByteReader, shieldID int32, enableLimits bool) protocol.IO {
	return &packetBufferZeroCopyReader{
		IO:     protocol.NewReader(src, shieldID, enableLimits),
		buffer: src.(*bytes.Buffer),
	}
}

type packetBufferZeroCopyReader struct {
	protocol.IO
	buffer *bytes.Buffer
}

// Bytes transfers the remaining input without copying it.
func (r *packetBufferZeroCopyReader) Bytes(dst *[]byte) {
	data := r.buffer.Bytes()
	*dst = data[:len(data):len(data)]
	r.buffer.Next(len(data))
}

// drainOwnedPacketBufferClassForTest removes retained buffers so the next release is deterministically reused.
func drainOwnedPacketBufferClassForTest(length int) [][]byte {
	for i := range ownedPacketBufferClasses {
		class := &ownedPacketBufferClasses[i]
		if length > class.size {
			continue
		}
		class.mu.Lock()
		count := len(class.buffers)
		class.mu.Unlock()
		buffers := make([][]byte, count)
		for i := range buffers {
			buffers[i] = acquireOwnedPacketBuffer(length)
		}
		return buffers
	}
	return nil
}

// Read keeps Decoder on its packet-oriented transport path.
func (r *packetBufferBatchReader) Read([]byte) (int, error) { return 0, io.EOF }

// ReadPacket returns the next complete recorded encoder batch.
func (r *packetBufferBatchReader) ReadPacket() ([]byte, error) {
	if r.next == len(r.batches) {
		return nil, io.EOF
	}
	batch := r.batches[r.next]
	r.next++
	return batch, nil
}

// remaining reports how many recorded batches have not been decoded.
func (r *packetBufferBatchReader) remaining() int {
	return len(r.batches) - r.next
}

// packetBufferPayloadOrder decodes the first byte of every captured unknown packet payload.
func packetBufferPayloadOrder(t *testing.T, batches [][]byte) []byte {
	t.Helper()
	reader := &packetBufferBatchReader{batches: batches}
	decoder := packet.NewDecoder(reader)
	var payloads []byte
	for reader.remaining() != 0 {
		frames, err := decoder.Decode()
		if err != nil {
			t.Fatal(err)
		}
		for _, frame := range frames {
			data, err := parseData(frame, &Conn{})
			if err != nil {
				t.Fatal(err)
			}
			payloads = append(payloads, data.payload.Bytes()[0])
		}
	}
	return payloads
}

var _ io.Reader = packetBufferBenchmarkTransport{}
