package minecraft

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// BenchmarkPreparedDialCommit models an 80ms proof mint and 50ms settings reply.
// Preparation is outside the ready-commit measurement, as it precedes the user's click.
func BenchmarkPreparedDialCommit(b *testing.B) {
	for _, prepared := range []bool{false, true} {
		name := "ordinary"
		if prepared {
			name = "ready_preparation"
		}
		b.Run(name, func(b *testing.B) {
			_, source := preparedAuthenticationFixture(b)
			source.started, source.delay = nil, 80*time.Millisecond
			d := Dialer{FlushRate: -1, RelayStartup: true, TokenSource: source}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				b.StopTimer()
				network := newScriptedDialNetwork(func(conn net.Conn) error {
					time.Sleep(50 * time.Millisecond)
					decoder, encoder, err := preparedScriptSettings(conn)
					if err != nil {
						return err
					}
					if _, err := preparedScriptRead(decoder, packet.IDLogin); err != nil {
						return err
					}
					if err := preparedScriptFinish(decoder, encoder); err != nil {
						return err
					}
					return expectScriptedClose(conn, decoder)
				})
				var p *PreparedDial
				if prepared {
					var err error
					p, err = d.PrepareContextNetwork(context.Background(), network, "127.0.0.1:19132", 7)
					if err != nil {
						b.Fatal(err)
					}
					<-p.Done()
					if !p.Ready() {
						b.Fatal(p.Err())
					}
				}
				b.StartTimer()
				var conn *Conn
				var err error
				if prepared {
					conn, err = p.CommitContext(context.Background(), d, "127.0.0.1:19132", 7)
				} else {
					conn, err = d.DialContextNetwork(context.Background(), network, "127.0.0.1:19132")
				}
				b.StopTimer()
				if err != nil {
					b.Fatal(err)
				}
				_ = conn.Close()
				if p != nil {
					_ = p.Close()
				}
				if err := <-network.done; err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
			}
		})
	}
}
