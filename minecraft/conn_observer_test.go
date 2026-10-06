package minecraft

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

func TestConn_PacketObserversFollowSerializedWritesAndDelayedDelivery(t *testing.T) {
	conn, ids := newSendDelayConn(t)
	conn.SetSendDelay(time.Hour)
	queued := make(chan uint32, 2)
	sent := make(chan uint32, 2)
	var writers sync.WaitGroup
	for _, id := range []uint32{700, 701} {
		writers.Add(1)
		go func() {
			defer writers.Done()
			err := conn.WritePacketObserved(testPacket(id), func(packet.Packet) {
				if conn.sendMu.TryLock() {
					conn.sendMu.Unlock()
					t.Error("queue observer ran outside write lock")
				}
				queued <- id
			}, func() { sent <- id })
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
	conn.SetSendDelay(time.Hour)
	sent := make(chan struct{}, 1)
	if err := conn.WritePacketObserved(testPacket(700), nil, func() { sent <- struct{}{} }); err != nil {
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
		write func(*Conn, func()) error
	}{
		{"Flush", func(conn *Conn, sent func()) error {
			if err := conn.WritePacketObserved(testPacket(700), nil, sent); err != nil {
				return err
			}
			return conn.Flush()
		}},
		{"WritePacketDirect", func(conn *Conn, _ func()) error {
			return conn.WritePacketDirect(testPacket(700))
		}},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			conn, _ := newSendDelayConn(t)
			conn.SetSendDelay(time.Hour)
			encoded, resume := make(chan struct{}), make(chan struct{})
			resumeEncoding := sync.OnceFunc(func() { close(resume) })
			t.Cleanup(resumeEncoding)
			conn.SetPacketBatchFunc(func(packet.BatchEncodeStats) {
				// Pause after encoding but before the delay writer receives the batch.
				close(encoded)
				<-resume
			})
			sent := make(chan struct{}, 1)
			finished := make(chan error, 1)
			go func() {
				defer close(finished)
				finished <- operation.write(conn, func() { sent <- struct{}{} })
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
			held, observers := len(conn.delay.held), len(conn.delay.nextObservers)
			conn.delay.mu.Unlock()
			if held != 0 || observers != 0 {
				t.Errorf("aborted connection retained %d delayed batches and %d pending observers", held, observers)
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
			if err := conn.WritePacketObserved(testPacket(700), nil, func() { sent <- struct{}{} }); err != nil {
				t.Fatal(err)
			}
			if err := conn.Flush(); err != nil {
				t.Fatal(err)
			}
			if failure {
				if err := conn.delay.set(0); err == nil {
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
