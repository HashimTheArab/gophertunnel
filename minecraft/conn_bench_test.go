package minecraft

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

type benchmarkConn struct{}

func (benchmarkConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (benchmarkConn) Write(b []byte) (int, error)      { return len(b), nil }
func (benchmarkConn) Close() error                     { return nil }
func (benchmarkConn) LocalAddr() net.Addr              { return benchmarkAddr("local") }
func (benchmarkConn) RemoteAddr() net.Addr             { return benchmarkAddr("remote") }
func (benchmarkConn) SetDeadline(time.Time) error      { return nil }
func (benchmarkConn) SetReadDeadline(time.Time) error  { return nil }
func (benchmarkConn) SetWriteDeadline(time.Time) error { return nil }

type benchmarkAddr string

func (a benchmarkAddr) Network() string { return string(a) }
func (a benchmarkAddr) String() string  { return string(a) }

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

func benchmarkPayload(n int) []byte {
	payload := make([]byte, n)
	for i := range payload {
		payload[i] = byte(i)
	}
	return payload
}
