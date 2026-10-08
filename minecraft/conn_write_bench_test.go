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
				if err := conn.SetSendDelay(delay); err != nil {
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
