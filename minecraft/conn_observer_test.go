package minecraft

import (
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
