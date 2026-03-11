package minecraft

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

func BenchmarkPackets(b *testing.B) {
	// Swap benchmark packets here. These need to be pointers because the packet
	// implementations expose ID/Marshal on pointer receivers.
	pks := []packet.Packet{
		&packet.Disconnect{
			Reason:                  packet.DisconnectReasonTimeout,
			HideDisconnectionScreen: false,
			Message:                 "Server maintenance in 5 minutes",
			FilteredMessage:         "Server maintenance",
		},
	}

	encodeConn := newBenchmarkConn()
	encoded := make([][]byte, 0, len(pks))
	encodeConn.encodePacketsTo(&encoded, pks...)
	if len(encoded) == 0 {
		b.Fatal("encode produced no packets")
	}

	totalBytes := 0
	for _, raw := range encoded {
		totalBytes += len(raw)
	}

	b.Run("encode", func(b *testing.B) {
		buf := make([][]byte, 0, len(encoded))
		b.ReportAllocs()
		b.SetBytes(int64(totalBytes))
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			buf = buf[:0]
			encodeConn.encodePacketsTo(&buf, pks...)
		}
	})

	decodeConn := newBenchmarkConn()
	b.Run("decode", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(totalBytes))
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			for _, raw := range encoded {
				data, err := parseData(raw, decodeConn)
				if err != nil {
					b.Fatalf("parse packet: %v", err)
				}
				decoded, err := data.decode(decodeConn)
				if err != nil {
					b.Fatalf("decode packet: %v", err)
				}
				if len(decoded) == 0 {
					b.Fatal("decode produced no packets")
				}
			}
		}
	})
}

func newBenchmarkConn() *Conn {
	conn := newConn(benchmarkNetConn{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), proto{}, 0, false, nil)
	conn.pool = benchmarkPacketPool()
	conn.readDeadline = make(chan time.Time)
	return conn
}

func benchmarkPacketPool() packet.Pool {
	pool := packet.NewServerPool()
	for id, fn := range packet.NewClientPool() {
		pool[id] = fn
	}
	return pool
}

type benchmarkNetConn struct{}

func (benchmarkNetConn) Read(_ []byte) (int, error)       { return 0, io.EOF }
func (benchmarkNetConn) Write(b []byte) (int, error)      { return len(b), nil }
func (benchmarkNetConn) Close() error                     { return nil }
func (benchmarkNetConn) LocalAddr() net.Addr              { return benchmarkAddr("local") }
func (benchmarkNetConn) RemoteAddr() net.Addr             { return benchmarkAddr("remote") }
func (benchmarkNetConn) SetDeadline(time.Time) error      { return nil }
func (benchmarkNetConn) SetReadDeadline(time.Time) error  { return nil }
func (benchmarkNetConn) SetWriteDeadline(time.Time) error { return nil }
func (benchmarkNetConn) Context() context.Context         { return context.Background() }

type benchmarkAddr string

func (a benchmarkAddr) Network() string { return "benchmark" }
func (a benchmarkAddr) String() string  { return string(a) }
