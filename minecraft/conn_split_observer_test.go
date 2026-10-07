package minecraft

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// expandingWriteProtocol makes packet 701 span more than one transport batch.
type expandingWriteProtocol struct{ Protocol }

// ConvertFromLatest expands one logical packet while leaving the surrounding packets unchanged.
func (p expandingWriteProtocol) ConvertFromLatest(pk packet.Packet, conn *Conn) []packet.Packet {
	if pk.ID() != 701 {
		return p.Protocol.ConvertFromLatest(pk, conn)
	}
	packets := make([]packet.Packet, 2000)
	for i := range packets {
		packets[i] = pk
	}
	return packets
}

// splitBatchTransport accepts complete writes except for an optional failing write number.
type splitBatchTransport struct {
	writes int
	failAt int
}

// Write accepts the batch or reports the configured failure without accepting any bytes.
func (w *splitBatchTransport) Write(data []byte) (int, error) {
	w.writes++
	if w.writes == w.failAt {
		return 0, net.ErrClosed
	}
	return len(data), nil
}

func TestConn_SplitBatchesCompleteOnlyAcceptedLogicalPackets(t *testing.T) {
	for _, mode := range []SendMode{Buffered, FlushBuffered, BypassBuffered} {
		for _, delay := range []time.Duration{0, time.Hour} {
			for _, failAt := range []int{0, 2} {
				t.Run(fmt.Sprintf("mode=%d/delay=%s/failAt=%d", mode, delay, failAt), func(t *testing.T) {
					conn, _ := newSendDelayConn(t)
					transport := &splitBatchTransport{failAt: failAt}
					conn.delay.w = transport
					conn.proto = expandingWriteProtocol{DefaultProtocol}
					if err := conn.SetSendDelay(delay); err != nil {
						t.Fatal(err)
					}
					var completed []uint32
					conn.SetWriteObserver(func(pk packet.Packet) func() {
						id := pk.ID()
						return func() { completed = append(completed, id) }
					})
					err := conn.WritePacket(mode, testPacket(700), testPacket(701), testPacket(702))
					if mode == Buffered && err == nil {
						err = conn.Flush()
					}
					if delay > 0 {
						if err != nil {
							t.Fatal(err)
						}
						if len(completed) != 0 {
							t.Fatalf("held packets completed early: %v", completed)
						}
						conn.delay.mu.Lock()
						if len(conn.delay.held) != 2 {
							conn.delay.mu.Unlock()
							t.Fatal("test packets did not produce two held batches")
						}
						conn.delay.held[0].due = time.Time{}
						err = conn.delay.releaseLocked(false)
						conn.delay.mu.Unlock()
						if err != nil {
							t.Fatal(err)
						}
						if !slices.Equal(completed, []uint32{700}) {
							t.Fatalf("first split completed %v, want only packet 700", completed)
						}
						err = conn.SetSendDelay(0)
					}
					want := []uint32{700, 701, 702}
					if failAt != 0 {
						want = []uint32{700}
						if !errors.Is(err, net.ErrClosed) {
							t.Fatalf("second split failure = %v, want net.ErrClosed", err)
						}
					} else if err != nil {
						t.Fatal(err)
					}
					if !slices.Equal(completed, want) {
						t.Fatalf("completed packets = %v, want %v", completed, want)
					}
					conn.delay.mu.Lock()
					staged, cursor := len(conn.delay.nextObservers), conn.delay.encodedPackets
					conn.delay.mu.Unlock()
					if staged != 0 || cursor != 0 {
						t.Fatalf("finished submission retained %d callbacks and cursor %d", staged, cursor)
					}
				})
			}
		}
	}
}

func TestConn_SplitBatchesKeepOwnersAcrossBufferedAndBypassWrites(t *testing.T) {
	for _, failAt := range []int{0, 3} {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			conn, _ := newSendDelayConn(t)
			conn.delay.w = &splitBatchTransport{failAt: failAt}
			conn.proto = expandingWriteProtocol{DefaultProtocol}
			if err := conn.SetSendDelay(time.Hour); err != nil {
				t.Fatal(err)
			}
			var completed []string
			conn.SetWriteObserver(func(pk packet.Packet) func() {
				id := pk.ID()
				return func() { completed = append(completed, fmt.Sprintf("old:%d", id)) }
			})
			// Raw writes occupy wire packet slots without acquiring a logical completion.
			var raw bytes.Buffer
			if err := (&packet.Header{PacketID: 704}).Write(&raw); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write(raw.Bytes()); err != nil {
				t.Fatal(err)
			}
			if err := conn.WritePacket(Buffered, testPacket(700), testPacket(701)); err != nil {
				t.Fatal(err)
			}
			conn.SetWriteObserver(func(pk packet.Packet) func() {
				id := pk.ID()
				return func() { completed = append(completed, fmt.Sprintf("new:%d", id)) }
			})
			if err := conn.WritePacket(BypassBuffered, testPacket(702)); err != nil {
				t.Fatal(err)
			}
			if err := conn.WritePacket(FlushBuffered, testPacket(703)); err != nil {
				t.Fatal(err)
			}
			conn.SetWriteObserver(nil)
			conn.delay.mu.Lock()
			if len(conn.delay.held) != 3 {
				conn.delay.mu.Unlock()
				t.Fatal("test packets did not produce three held batches")
			}
			conn.delay.held[0].due = time.Time{}
			conn.delay.held[1].due = time.Time{}
			err := conn.delay.releaseLocked(false)
			conn.delay.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"new:702", "old:700"}
			if !slices.Equal(completed, want) {
				t.Fatalf("first two batches completed %v, want %v", completed, want)
			}
			err = conn.SetSendDelay(0)
			if failAt == 0 {
				if err != nil {
					t.Fatal(err)
				}
				want = append(want, "old:701", "new:703")
			} else if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("final split failure = %v, want net.ErrClosed", err)
			}
			if !slices.Equal(completed, want) {
				t.Fatalf("completed packets = %v, want %v", completed, want)
			}
		})
	}
}
