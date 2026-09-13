package minecraft

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// benchmarkConn discards encoded output without adding transport allocations.
type benchmarkConn struct{}

// Read reports that the fake transport has no incoming data.
func (benchmarkConn) Read([]byte) (int, error) { return 0, io.EOF }

// Write accepts a complete batch without retaining it.
func (benchmarkConn) Write(b []byte) (int, error) { return len(b), nil }

// Close has no resources to release.
func (benchmarkConn) Close() error { return nil }

// LocalAddr returns a fixed local endpoint.
func (benchmarkConn) LocalAddr() net.Addr { return benchmarkAddr("local") }

// RemoteAddr returns a fixed remote endpoint.
func (benchmarkConn) RemoteAddr() net.Addr { return benchmarkAddr("remote") }

// SetDeadline accepts deadlines without starting timers.
func (benchmarkConn) SetDeadline(time.Time) error { return nil }

// SetReadDeadline accepts read deadlines without starting timers.
func (benchmarkConn) SetReadDeadline(time.Time) error { return nil }

// SetWriteDeadline accepts write deadlines without starting timers.
func (benchmarkConn) SetWriteDeadline(time.Time) error { return nil }

type benchmarkAddr string

// Network returns the fake endpoint name.
func (a benchmarkAddr) Network() string { return string(a) }

// String returns the fake endpoint name.
func (a benchmarkAddr) String() string { return string(a) }

func BenchmarkConnWritePacket(b *testing.B) {
	conn := newConn(benchmarkConn{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), DefaultProtocol, 0, false)
	pk := &packet.Unknown{
		PacketID: packet.IDText,
		Payload:  benchmarkPayload(512),
	}

	b.ReportAllocs()
	for b.Loop() {
		if err := conn.WritePacket(pk); err != nil {
			b.Fatal(err)
		}
		conn.bufferedSend.release()
	}
}

func BenchmarkConnWritePacketFlush(b *testing.B) {
	conn := newConn(benchmarkConn{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), DefaultProtocol, 0, false)
	pk := &packet.Unknown{
		PacketID: packet.IDText,
		Payload:  benchmarkPayload(512),
	}

	b.ReportAllocs()
	for b.Loop() {
		if err := conn.WritePacket(pk); err != nil {
			b.Fatal(err)
		}
		if err := conn.Flush(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConnWritePacketDirect(b *testing.B) {
	conn := newConn(benchmarkConn{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), DefaultProtocol, 0, false)
	pk := &packet.Unknown{
		PacketID: packet.IDText,
		Payload:  benchmarkPayload(512),
	}

	b.ReportAllocs()
	for b.Loop() {
		if err := conn.WritePacketDirect(pk); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConnWritePacketDirectBatch(b *testing.B) {
	conn := newConn(benchmarkConn{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), DefaultProtocol, 0, false)
	payload := benchmarkPayload(512)
	packets := make([]packet.Packet, 16)
	for i := range packets {
		packets[i] = &packet.Unknown{PacketID: packet.IDText, Payload: payload}
	}

	b.ReportAllocs()
	for b.Loop() {
		if err := conn.WritePacketDirect(packets...); err != nil {
			b.Fatal(err)
		}
	}
}

// benchmarkPayload returns a repeatable payload with both changing and repeated bytes.
func benchmarkPayload(n int) []byte {
	payload := make([]byte, n)
	for i := range payload {
		payload[i] = byte(i)
	}
	return payload
}

// BenchmarkConnBufferedBatch measures proxy-style batches through real packet marshaling and compression.
func BenchmarkConnBufferedBatch(b *testing.B) {
	movement := make([]packet.Packet, 32)
	for i := range movement {
		movement[i] = &packet.MovePlayer{EntityRuntimeID: uint64(i + 100), OnGround: true, Tick: uint64(i + 1)}
	}
	mixed := append([]packet.Packet{&packet.LevelChunk{SubChunkCount: 4, RawPayload: benchmarkPayload(64 * 1024)}}, movement[:16]...)
	for _, workload := range []struct {
		name    string
		packets []packet.Packet
	}{
		{"input", []packet.Packet{&packet.PlayerAuthInput{Tick: 100}}},
		{"movement32", movement},
		{"chunk-and-movement", mixed},
	} {
		for _, mode := range []struct {
			name                  string
			compression           packet.Compression
			encrypted, translated bool
			protocol              Protocol
		}{
			{"plain", nil, false, false, DefaultProtocol},
			{"snappy", packet.SnappyCompression, false, false, DefaultProtocol},
			{"flate-encrypted", packet.FlateCompression, true, false, DefaultProtocol},
			{"snappy-translated", packet.SnappyCompression, false, true, DefaultProtocol},
			{"snappy-legacy", packet.SnappyCompression, false, false, Protocol12644()},
		} {
			b.Run(workload.name+"/"+mode.name, func(b *testing.B) {
				conn := newConn(benchmarkConn{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), mode.protocol, 0, false)
				if mode.compression != nil {
					conn.enc.EnableCompression(mode.compression, 256)
				}
				if mode.encrypted {
					conn.enc.EnableEncryption([32]byte{1})
				}
				if mode.translated {
					conn.SetActorIDTranslation(&protocol.ActorIDTranslation{RuntimeID: func(id uint64) uint64 { return id + 1 }})
				}
				if err := conn.WritePacketImmediate(workload.packets...); err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				for b.Loop() {
					for _, pk := range workload.packets {
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
}
