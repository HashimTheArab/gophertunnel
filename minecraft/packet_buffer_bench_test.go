package minecraft

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

type packetBufferBenchmarkTransport struct{}

// Read implements net.Conn for outgoing-only benchmarks.
func (packetBufferBenchmarkTransport) Read([]byte) (int, error) { return 0, io.EOF }

// Write discards an encoded batch without adding benchmark allocations.
func (packetBufferBenchmarkTransport) Write(p []byte) (int, error) { return len(p), nil }

// Close implements net.Conn for benchmark connections.
func (packetBufferBenchmarkTransport) Close() error { return nil }

// LocalAddr returns the stable benchmark source address.
func (packetBufferBenchmarkTransport) LocalAddr() net.Addr {
	return packetBufferBenchmarkAddr("local")
}

// RemoteAddr returns the stable benchmark destination address.
func (packetBufferBenchmarkTransport) RemoteAddr() net.Addr {
	return packetBufferBenchmarkAddr("remote")
}

// SetDeadline implements net.Conn without affecting the in-memory transport.
func (packetBufferBenchmarkTransport) SetDeadline(time.Time) error { return nil }

// SetReadDeadline implements net.Conn without affecting the in-memory transport.
func (packetBufferBenchmarkTransport) SetReadDeadline(time.Time) error { return nil }

// SetWriteDeadline implements net.Conn without affecting the in-memory transport.
func (packetBufferBenchmarkTransport) SetWriteDeadline(time.Time) error { return nil }

type packetBufferBenchmarkAddr string

// Network returns the benchmark address label.
func (a packetBufferBenchmarkAddr) Network() string { return string(a) }

// String returns the benchmark address label.
func (a packetBufferBenchmarkAddr) String() string { return string(a) }

// BenchmarkConnPacketBuffer measures the synchronous marshal, buffered ownership and flush path.
func BenchmarkConnPacketBuffer(b *testing.B) {
	tests := []struct {
		name    string
		packets []packet.Packet
	}{
		{name: "small_tick", packets: []packet.Packet{&packet.PlayerAuthInput{}}},
		{name: "mixed_batch", packets: packetBufferMixedBatch()},
		{name: "large_payload", packets: []packet.Packet{&packet.Unknown{PacketID: 700, Payload: make([]byte, 256<<10)}}},
	}
	for _, test := range tests {
		b.Run(test.name, func(b *testing.B) {
			conn := newConn(packetBufferBenchmarkTransport{}, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				for _, pk := range test.packets {
					if err := conn.WritePacket(pk); err != nil {
						b.Fatal(err)
					}
				}
				if err := conn.Flush(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkPacketDataOwnership measures retaining borrowed decoder packet slices for later reads.
func BenchmarkPacketDataOwnership(b *testing.B) {
	tests := []struct {
		name   string
		frames [][]byte
	}{
		{name: "small_tick", frames: packetBufferFrames(b, []packet.Packet{&packet.PlayerAuthInput{}})},
		{name: "mixed_batch", frames: packetBufferFrames(b, packetBufferMixedBatch())},
		{name: "large_payload", frames: packetBufferFrames(b, []packet.Packet{&packet.Unknown{PacketID: 700, Payload: make([]byte, 256<<10)}})},
	}
	for _, test := range tests {
		b.Run(test.name, func(b *testing.B) {
			conn := &Conn{batchReading: true, proto: DefaultProtocol}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				for _, frame := range test.frames {
					data := packetBufferData(frame)
					conn.collectPacket(data)
				}
				releasePacketData(conn.pendingBatch)
				conn.pendingBatch = conn.pendingBatch[:0]
			}
		})
	}
}

// packetBufferMixedBatch returns a representative per-tick mix of movement and small payload packets.
func packetBufferMixedBatch() []packet.Packet {
	packets := make([]packet.Packet, 0, 32)
	for range 8 {
		packets = append(packets,
			&packet.PlayerAuthInput{},
			&packet.MovePlayer{},
			&packet.Unknown{PacketID: 700, Payload: make([]byte, 96)},
			&packet.PlayStatus{},
		)
	}
	return packets
}

// packetBufferFrames encodes packets once so ownership benchmarks exclude outgoing marshaling.
func packetBufferFrames(b *testing.B, packets []packet.Packet) [][]byte {
	b.Helper()
	conn := &Conn{proto: DefaultProtocol, hdr: &packet.Header{}}
	var queue packetQueue
	conn.encodePacketsTo(&queue, packets...)
	return queue.packets
}

// packetBufferData constructs borrowed packet data without including header parsing in ownership measurements.
func packetBufferData(frame []byte) *packetData {
	header := &packet.Header{}
	buf := bytes.NewBuffer(frame)
	_ = header.Read(buf)
	return &packetData{h: header, full: frame, payload: buf}
}
