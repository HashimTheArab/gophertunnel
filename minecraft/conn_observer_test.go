package minecraft

import (
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

func TestConn_WriteModesObserveEveryPacketAndPreserveBatchOrder(t *testing.T) {
	for _, mode := range []sendMode{buffered, flushBuffered, bypassBuffered} {
		for _, delay := range []time.Duration{0, time.Hour} {
			t.Run(fmt.Sprintf("mode=%d/delay=%s", mode, delay), func(t *testing.T) {
				conn, ids := newSendDelayConn(t)
				if err := conn.SetSendDelay(delay); err != nil {
					t.Fatal(err)
				}
				var captures []uint32
				sent := make(chan uint32, 3)
				conn.SetWriteObserver(func(pk packet.Packet) func() {
					id := pk.ID()
					captures = append(captures, id)
					return func() { sent <- id }
				})
				if err := conn.WritePacket(testPacket(700)); err != nil {
					t.Fatal(err)
				}
				if err := conn.writePackets(mode, testPacket(701), testPacket(702)); err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(captures, []uint32{700, 701, 702}) {
					t.Fatalf("capture order = %v", captures)
				}
				if delay > 0 || mode == buffered {
					select {
					case id := <-sent:
						t.Fatalf("packet %d completed before its batch was released", id)
					default:
					}
				}
				if err := conn.Flush(); err != nil {
					t.Fatal(err)
				}
				if err := conn.SetSendDelay(0); err != nil {
					t.Fatal(err)
				}
				want := []uint32{700, 701, 702}
				if mode == bypassBuffered {
					want = []uint32{701, 702, 700}
				}
				for _, id := range want {
					expectSent(t, ids, id, time.Second)
					expectSent(t, sent, id, time.Second)
				}
			})
		}
	}
}

func TestConn_ReplacingObserverKeepsBufferedAndDelayedCompletions(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	if err := conn.SetSendDelay(time.Hour); err != nil {
		t.Fatal(err)
	}
	oldSession, newSession := make(chan uint32, 1), make(chan uint32, 2)
	conn.SetWriteObserver(func(pk packet.Packet) func() {
		id := pk.ID()
		return func() { oldSession <- id }
	})
	if err := conn.WritePacket(testPacket(700)); err != nil {
		t.Fatal(err)
	}
	conn.SetWriteObserver(func(pk packet.Packet) func() {
		id := pk.ID()
		return func() { newSession <- id }
	})
	if err := conn.WritePacketImmediate(testPacket(701)); err != nil {
		t.Fatal(err)
	}
	conn.SetWriteObserver(nil)
	if err := conn.WritePacketImmediate(testPacket(702)); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetSendDelay(0); err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint32{700, 701, 702} {
		expectSent(t, ids, id, time.Second)
	}
	expectSent(t, oldSession, 700, time.Second)
	expectSent(t, newSession, 701, time.Second)
	select {
	case id := <-newSession:
		t.Fatalf("disabled observer captured packet %d", id)
	default:
	}
}

// splitWriteProtocol drops packet 700 and splits other packets into two wire packets.
type splitWriteProtocol struct{ Protocol }

// ConvertFromLatest supplies drop and split cases for logical packet observation.
func (p splitWriteProtocol) ConvertFromLatest(pk packet.Packet, _ *Conn) []packet.Packet {
	if pk.ID() == 700 {
		return nil
	}
	return []packet.Packet{testPacket(pk.ID()), testPacket(pk.ID() + 1)}
}

func TestConn_ObserverCapturesOnlyLogicalPacketsThatProduceWireData(t *testing.T) {
	for _, mode := range []sendMode{buffered, flushBuffered, bypassBuffered} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			conn, ids := newSendDelayConn(t)
			conn.proto = splitWriteProtocol{DefaultProtocol}
			var captures []uint32
			sent := make(chan uint32, 3)
			conn.SetWriteObserver(func(pk packet.Packet) func() {
				id := pk.ID()
				captures = append(captures, id)
				return func() { sent <- id }
			})
			if err := conn.writePackets(mode, testPacket(700), testPacket(701)); err != nil {
				t.Fatal(err)
			}
			if err := conn.Flush(); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(captures, []uint32{701}) {
				t.Fatalf("captured logical packets %v, want [701]", captures)
			}
			expectSent(t, ids, 701, time.Second)
			expectSent(t, ids, 702, time.Second)
			expectSent(t, sent, 701, time.Second)
			select {
			case id := <-sent:
				t.Fatalf("extra completion for packet %d", id)
			default:
			}
		})
	}
}

func TestConn_ConcurrentSubmittedWritesKeepCaptureAndTransportOrder(t *testing.T) {
	for _, delay := range []time.Duration{0, time.Hour} {
		t.Run(delay.String(), func(t *testing.T) {
			conn, ids := newSendDelayConn(t)
			if err := conn.SetSendDelay(delay); err != nil {
				t.Fatal(err)
			}
			var captures []uint32
			sent := make(chan uint32, 8)
			conn.SetWriteObserver(func(pk packet.Packet) func() {
				id := pk.ID()
				captures = append(captures, id)
				return func() { sent <- id }
			})
			var writers sync.WaitGroup
			for i := range 8 {
				writers.Go(func() {
					mode := flushBuffered
					if i%2 == 0 {
						mode = bypassBuffered
					}
					if err := conn.writePackets(mode, testPacket(uint32(700+i))); err != nil {
						t.Error(err)
					}
				})
			}
			writers.Wait()
			if err := conn.SetSendDelay(0); err != nil {
				t.Fatal(err)
			}
			if len(captures) != 8 {
				t.Fatalf("captured %d packets, want 8", len(captures))
			}
			for _, id := range captures {
				expectSent(t, ids, id, time.Second)
				expectSent(t, sent, id, time.Second)
			}
		})
	}
}

// recoveringWriter fails its first write and would accept later writes if they reached it.
type recoveringWriter struct {
	failure io.Writer
	writes  int
}

// Write injects one failure, then accepts complete batches.
func (w *recoveringWriter) Write(data []byte) (int, error) {
	w.writes++
	if w.writes == 1 {
		return w.failure.Write(data)
	}
	return len(data), nil
}

func TestConn_TransportFailureIsTerminal(t *testing.T) {
	for _, mode := range []sendMode{buffered, flushBuffered, bypassBuffered} {
		for _, encrypted := range []bool{false, true} {
			for _, failure := range []struct {
				name   string
				writer io.Writer
				err    error
			}{
				{"error", failingWriter{}, net.ErrClosed},
				{"short", shortWriter{}, io.ErrShortWrite},
			} {
				t.Run(fmt.Sprintf("mode=%d/encrypted=%t/%s", mode, encrypted, failure.name), func(t *testing.T) {
					conn, _ := newSendDelayConn(t)
					transport := &recoveringWriter{failure: failure.writer}
					conn.delay.w = transport
					if encrypted {
						conn.enc.EnableEncryption([32]byte{1, 2, 3, 4})
					}
					completions := 0
					conn.SetWriteObserver(func(packet.Packet) func() {
						return func() { completions++ }
					})
					for _, id := range []uint32{700, 701} {
						err := conn.writePackets(mode, testPacket(id))
						if mode == buffered {
							if err != nil {
								t.Fatal(err)
							}
							err = conn.Flush()
						}
						if !errors.Is(err, failure.err) {
							t.Errorf("send %d = %v, want %v", id, err, failure.err)
						}
						if err := conn.Flush(); !errors.Is(err, failure.err) {
							t.Errorf("empty Flush = %v, want %v", err, failure.err)
						}
					}
					for _, delay := range []time.Duration{time.Hour, 0} {
						if err := conn.SetSendDelay(delay); !errors.Is(err, failure.err) {
							t.Errorf("SetSendDelay(%v) = %v, want %v", delay, err, failure.err)
						}
					}
					if transport.writes != 1 || completions != 0 {
						t.Errorf("transport writes = %d, completions = %d; want 1, 0", transport.writes, completions)
					}
					if len(conn.delay.nextObservers) != 0 || len(conn.delay.held) != 0 {
						t.Error("failed send retained pending completions or batches")
					}
				})
			}
		}
	}
}

func TestConn_PacketObserversFollowSerializedWritesAndDelayedDelivery(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	if err := conn.SetSendDelay(time.Hour); err != nil {
		t.Fatal(err)
	}
	queued := make(chan uint32, 2)
	sent := make(chan uint32, 2)
	conn.SetWriteObserver(func(pk packet.Packet) func() {
		if conn.sendMu.TryLock() {
			conn.sendMu.Unlock()
			t.Error("queue observer ran outside write lock")
		}
		id := pk.ID()
		queued <- id
		return func() { sent <- id }
	})
	var writers sync.WaitGroup
	for _, id := range []uint32{700, 701} {
		writers.Add(1)
		go func() {
			defer writers.Done()
			err := conn.WritePacket(testPacket(id))
			if err != nil {
				t.Error(err)
			}
		}()
	}
	writers.Wait()
	first, second := <-queued, <-queued
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sent:
		t.Fatal("delivery observed before delay release")
	default:
	}
	conn.SetSendDelay(0)
	expectSent(t, ids, first, time.Second)
	expectSent(t, ids, second, time.Second)
	for _, want := range []uint32{first, second} {
		select {
		case got := <-sent:
			if got != want {
				t.Fatalf("delivery observer=%d want %d", got, want)
			}
		case <-time.After(time.Second):
			t.Fatal("missing delivery observer")
		}
	}
}

func TestConn_AbortDiscardsDeliveryObservers(t *testing.T) {
	conn, _ := newSendDelayConn(t)
	if err := conn.SetSendDelay(time.Hour); err != nil {
		t.Fatal(err)
	}
	sent := make(chan struct{}, 1)
	conn.SetWriteObserver(func(packet.Packet) func() { return func() { sent <- struct{}{} } })
	if err := conn.WritePacket(testPacket(700)); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	_ = conn.Abort()
	conn.SetSendDelay(0)
	select {
	case <-sent:
		t.Fatal("aborted packet reported delivery")
	default:
	}
}

func TestConn_AbortDiscardsInFlightDelayedWrites(t *testing.T) {
	operations := []struct {
		name  string
		write func(*Conn) error
	}{
		{"Flush", func(conn *Conn) error {
			if err := conn.WritePacket(testPacket(700)); err != nil {
				return err
			}
			return conn.Flush()
		}},
		{"flushBuffered", func(conn *Conn) error { return conn.WritePacketImmediate(testPacket(700)) }},
		{"bypassBuffered", func(conn *Conn) error { return conn.WritePacketDirect(testPacket(700)) }},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			conn, _ := newSendDelayConn(t)
			if err := conn.SetSendDelay(time.Hour); err != nil {
				t.Fatal(err)
			}
			encoded, resume := make(chan struct{}), make(chan struct{})
			resumeEncoding := sync.OnceFunc(func() { close(resume) })
			t.Cleanup(resumeEncoding)
			conn.SetPacketBatchFunc(func(packet.BatchEncodeStats) {
				// Pause after encoding but before the delay writer receives the batch.
				close(encoded)
				<-resume
			})
			sent := make(chan struct{}, 1)
			conn.SetWriteObserver(func(packet.Packet) func() { return func() { sent <- struct{}{} } })
			finished := make(chan error, 1)
			go func() {
				defer close(finished)
				finished <- operation.write(conn)
			}()
			select {
			case <-encoded:
			case <-time.After(time.Second):
				t.Fatal("write did not reach batch encoding")
			}
			if err := conn.Abort(); err != nil {
				t.Fatal(err)
			}
			resumeEncoding()
			select {
			case err := <-finished:
				if !errors.Is(err, net.ErrClosed) {
					t.Errorf("write after abort = %v, want net.ErrClosed", err)
				}
			case <-time.After(time.Second):
				t.Fatal("write did not finish after abort")
			}
			conn.delay.mu.Lock()
			held, observers, cursor := len(conn.delay.held), len(conn.delay.nextObservers), conn.delay.encodedPackets
			conn.delay.mu.Unlock()
			if held != 0 || observers != 0 || cursor != 0 {
				t.Errorf("aborted connection retained %d delayed batches, %d pending observers and cursor %d", held, observers, cursor)
			}
			select {
			case <-sent:
				t.Fatal("aborted write reported delivery")
			default:
			}
		})
	}
}

func TestConn_DeliveryObserversRunFromTimerAndIgnoreFailedWrites(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "timer", true: "failed transport"}[failure], func(t *testing.T) {
			conn, _ := newSendDelayConn(t)
			if failure {
				conn.delay.w = failingWriter{}
			}
			conn.SetSendDelay(20 * time.Millisecond)
			sent := make(chan struct{}, 1)
			conn.SetWriteObserver(func(packet.Packet) func() { return func() { sent <- struct{}{} } })
			if err := conn.WritePacket(testPacket(700)); err != nil {
				t.Fatal(err)
			}
			if err := conn.Flush(); err != nil {
				t.Fatal(err)
			}
			if failure {
				if err := conn.SetSendDelay(0); err == nil {
					t.Fatal("expected transport error")
				}
				select {
				case <-sent:
					t.Fatal("failed write observed as delivered")
				default:
				}
			} else {
				select {
				case <-sent:
				case <-time.After(time.Second):
					t.Fatal("timer did not observe delivery")
				}
			}
		})
	}
}
