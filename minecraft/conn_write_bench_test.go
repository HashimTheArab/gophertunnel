package minecraft

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// BenchmarkConn_WritePacket compares a 16-packet batch with observation disabled, capture only, and
// a captured completion per packet. Delayed batches are released explicitly to bound retained memory
// and measure their allocation cost without waiting for a wall-clock delay.
func BenchmarkConn_WritePacket(b *testing.B) {
	for _, delay := range []time.Duration{0, time.Hour} {
		for _, observation := range []string{"none", "capture", "completion"} {
			b.Run(fmt.Sprintf("delay=%s/observer=%s", delay, observation), func(b *testing.B) {
				client, peer := net.Pipe()
				conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
				conn.delay.w = io.Discard
				b.Cleanup(func() {
					_ = conn.Abort()
					_ = peer.Close()
				})
				if err := setSendDelay(conn, delay); err != nil {
					b.Fatal(err)
				}
				var observed uint32
				switch observation {
				case "capture":
					conn.SetWriteObserver(func(pk packet.Packet) func() {
						observed += pk.ID()
						return nil
					})
				case "completion":
					conn.SetWriteObserver(func(pk packet.Packet) func() {
						id := pk.ID()
						return func() { observed += id }
					})
				}
				packets := make([]packet.Packet, 16)
				for i := range packets {
					packets[i] = testPacket(uint32(700 + i))
				}
				b.ReportAllocs()
				for b.Loop() {
					if err := conn.WritePacketImmediate(packets...); err != nil {
						b.Fatal(err)
					}
					if delay > 0 {
						conn.delay.mu.Lock()
						err := conn.delay.releaseLocked(true)
						conn.delay.mu.Unlock()
						if err != nil {
							b.Fatal(err)
						}
					}
				}
			})
		}
	}
}

// BenchmarkConn_WritePacketHeld writes a 16-packet batch with no hold, with a manual hold keeping half of
// it, released every 64 held packets as a holding caller's limit releases them, with a delay on every
// packet, and with both. The steady state includes the releases; delayed batches are released explicitly
// to bound retained memory without waiting for a wall-clock delay.
func BenchmarkConn_WritePacketHeld(b *testing.B) {
	for _, mode := range []struct {
		name          string
		manual, delay bool
	}{{"none", false, false}, {"manual", true, false}, {"delay", false, true}, {"manual+delay", true, true}} {
		b.Run("hold="+mode.name, func(b *testing.B) {
			client, peer := net.Pipe()
			conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
			conn.delay.w = io.Discard
			b.Cleanup(func() {
				_ = conn.Abort()
				_ = peer.Close()
			})
			if mode.manual {
				hold := func(pk packet.Packet) PacketHoldDecision {
					if pk.ID()%2 == 0 {
						return PacketHoldKeep
					}
					return PacketHoldSend
				}
				if err := conn.NewPacketHold().Set(PacketHoldRule{Select: hold, Limit: 64}); err != nil {
					b.Fatal(err)
				}
			}
			if mode.delay {
				if err := conn.NewPacketHold().Set(PacketHoldRule{Delay: time.Hour}); err != nil {
					b.Fatal(err)
				}
			}
			packets := make([]packet.Packet, 16)
			for i := range packets {
				packets[i] = testPacket(uint32(700 + i))
			}
			b.ReportAllocs()
			for b.Loop() {
				for _, pk := range packets {
					if err := conn.WritePacket(pk); err != nil {
						b.Fatal(err)
					}
				}
				if err := conn.Flush(); err != nil {
					b.Fatal(err)
				}
				if mode.delay {
					conn.delay.mu.Lock()
					err := conn.delay.releaseLocked(true)
					conn.delay.mu.Unlock()
					if err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
