package minecraft

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// deferredCloseTransport models a transport whose Close schedules shutdown without unblocking Write.
type deferredCloseTransport struct {
	net.Conn
	started     chan struct{}
	release     chan struct{}
	startOnce   sync.Once
	releaseOnce sync.Once
	succeed     bool
	writes      atomic.Int32
}

// Write waits for the test to finish transport shutdown, optionally accepting the bytes despite Close.
func (c *deferredCloseTransport) Write(b []byte) (int, error) {
	c.writes.Add(1)
	c.startOnce.Do(func() { close(c.started) })
	<-c.release
	if c.succeed {
		return len(b), nil
	}
	return 0, net.ErrClosed
}

// Close requests shutdown but leaves the in-flight Write blocked, as a graceful transport may do.
func (*deferredCloseTransport) Close() error { return nil }

// unblock completes the pending write and may be used by both the test and its cleanup.
func (c *deferredCloseTransport) unblock() { c.releaseOnce.Do(func() { close(c.release) }) }

func TestConn_AbortDoesNotWaitForTransportShutdown(t *testing.T) {
	for _, delay := range []time.Duration{0, time.Hour} {
		for _, direct := range []bool{false, true} {
			for _, succeed := range []bool{false, true} {
				t.Run(fmt.Sprintf("delay=%s/direct=%t/success=%t", delay, direct, succeed), func(t *testing.T) {
					client, peer := net.Pipe()
					transport := &deferredCloseTransport{Conn: client, started: make(chan struct{}), release: make(chan struct{}), succeed: succeed}
					t.Cleanup(func() { transport.unblock(); _ = client.Close(); _ = peer.Close() })
					conn := newConn(transport, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
					t.Cleanup(func() { _ = conn.Abort() })
					if err := conn.SetSendDelay(delay); err != nil {
						t.Fatal(err)
					}
					sent := make(chan struct{}, 4)
					conn.SetWriteObserver(func(packet.Packet) func() { return func() { sent <- struct{}{} } })
					write := func() error {
						if direct {
							return conn.WritePacketDirect(testPacket(700))
						}
						if err := conn.WritePacket(testPacket(700)); err != nil {
							return err
						}
						return conn.Flush()
					}
					done := make(chan error, 1)
					if delay > 0 {
						// The second held batch must be discarded without another transport write.
						for range 2 {
							if err := write(); err != nil {
								t.Fatal(err)
							}
						}
						go func() { done <- conn.SetSendDelay(0) }()
					} else {
						go func() { done <- write() }()
					}
					select {
					case <-transport.started:
					case <-time.After(time.Second):
						t.Fatal("transport write did not start")
					}
					aborted := make(chan error, 1)
					go func() { aborted <- conn.Abort() }()
					select {
					case err := <-aborted:
						if err != nil {
							t.Fatal(err)
						}
					case <-time.After(time.Second):
						transport.unblock()
						<-done
						t.Fatal("Abort waited for a transport write after Close returned")
					}
					transport.unblock()
					if err := <-done; !errors.Is(err, net.ErrClosed) {
						t.Fatalf("write after Abort = %v, want net.ErrClosed", err)
					}
					select {
					case <-sent:
						t.Fatal("aborted write ran its completion")
					default:
					}
					if writes := transport.writes.Load(); writes != 1 {
						t.Fatalf("transport writes = %d, want 1", writes)
					}
					conn.delay.mu.Lock()
					defer conn.delay.mu.Unlock()
					if len(conn.delay.held) != 0 || conn.delay.nextObservers != nil || conn.delay.encodedPackets != 0 || conn.delay.err == nil {
						t.Fatalf("abort retained state: held=%d staged=%d cursor=%d err=%v", len(conn.delay.held), len(conn.delay.nextObservers), conn.delay.encodedPackets, conn.delay.err)
					}
				})
			}
		}
	}
}

// timerFailureTransport fails without closing its readable side, so the connection must notice the error.
type timerFailureTransport struct {
	net.Conn
	failed chan struct{}
	once   sync.Once
	err    error
}

// Write publishes the attempted send once, then returns the configured transport failure.
func (c *timerFailureTransport) Write([]byte) (int, error) {
	c.once.Do(func() { close(c.failed) })
	return 0, c.err
}

func TestConn_EmptyFlushReportsTimerFailure(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		t.Run(fmt.Sprintf("automatic=%t", automatic), func(t *testing.T) {
			client, peer := net.Pipe()
			t.Cleanup(func() { _ = client.Close(); _ = peer.Close() })
			transport := &timerFailureTransport{Conn: client, failed: make(chan struct{}), err: errors.New("transport rejected batch")}
			flushRate := time.Duration(-1)
			if automatic {
				flushRate = time.Millisecond
			}
			conn := newConn(transport, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, flushRate, false)
			t.Cleanup(func() { _ = conn.Abort() })
			if err := conn.SetSendDelay(time.Millisecond); err != nil {
				t.Fatal(err)
			}
			sent := make(chan struct{}, 1)
			conn.SetWriteObserver(func(packet.Packet) func() { return func() { sent <- struct{}{} } })
			if err := conn.WritePacketImmediate(testPacket(700)); err != nil {
				t.Fatal(err)
			}
			select {
			case <-transport.failed:
			case <-time.After(time.Second):
				t.Fatal("delayed send did not run")
			}
			if automatic {
				select {
				case <-conn.Context().Done():
				case <-time.After(time.Second):
					t.Fatal("periodic empty Flush did not close the failed connection")
				}
				if cause := context.Cause(conn.Context()); !errors.Is(cause, transport.err) {
					t.Fatalf("close cause = %v, want transport failure", cause)
				}
			} else if err := conn.Flush(); !errors.Is(err, transport.err) {
				t.Fatalf("empty Flush = %v, want transport failure", err)
			}
			select {
			case <-sent:
				t.Fatal("failed delayed write ran its completion")
			default:
			}
		})
	}
}

func TestDelayWriter_AbortMarkerIsTerminalBeforeCleanup(t *testing.T) {
	for _, operation := range []string{"set", "failure", "setObservers", "release"} {
		t.Run(operation, func(t *testing.T) {
			d := &delayWriter{held: []heldWrite{{data: []byte{1}, observers: []packetCompletion{{after: 1, sent: func() {}}}}}, nextObservers: []packetCompletion{{after: 1, sent: func() {}}}, encodedPackets: 1}
			// This is the state seen by a waiter that obtains mu before the previous owner's cleanup retry.
			d.aborted.Store(true)
			var err error
			switch operation {
			case "set":
				err = d.set(time.Hour)
			case "failure":
				err = d.failure()
			case "setObservers":
				d.setObservers([]packetCompletion{{after: 2, sent: func() {}}})
			case "release":
				d.mu.Lock()
				err = d.releaseLocked(true)
				d.unlock()
			}
			if operation != "setObservers" && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("%s = %v, want net.ErrClosed", operation, err)
			}
			if d.held != nil || d.nextObservers != nil || d.encodedPackets != 0 || !errors.Is(d.err, net.ErrClosed) {
				t.Fatalf("abort left queued references or no terminal error: %+v", d)
			}
		})
	}
}

func TestDelayWriter_AbortRacingUnlockClearsReferences(t *testing.T) {
	for range 1000 {
		d := &delayWriter{held: []heldWrite{{data: []byte{1}}}, nextObservers: []packetCompletion{{after: 1, sent: func() {}}}, encodedPackets: 1}
		d.mu.Lock()
		unlocked := make(chan struct{})
		go func() { d.unlock(); close(unlocked) }()
		d.drop()
		<-unlocked
		if d.held != nil || d.nextObservers != nil || d.encodedPackets != 0 || !errors.Is(d.err, net.ErrClosed) {
			t.Fatal("abort lost cleanup while the state lock was released")
		}
	}
}

func TestConn_CanceledCloseDoesNotWaitForTransportShutdown(t *testing.T) {
	for _, delay := range []time.Duration{0, time.Hour} {
		for _, closePath := range []string{"abortThenClose", "abort", "canceledContext"} {
			t.Run(fmt.Sprintf("delay=%s/path=%s", delay, closePath), func(t *testing.T) {
				client, peer := net.Pipe()
				transport := &deferredCloseTransport{Conn: client, started: make(chan struct{}), release: make(chan struct{}), succeed: true}
				t.Cleanup(func() { transport.unblock(); _ = client.Close(); _ = peer.Close() })
				conn := newConn(transport, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
				t.Cleanup(func() { _ = conn.Abort() })
				if err := conn.SetSendDelay(delay); err != nil {
					t.Fatal(err)
				}
				sent := make(chan struct{}, 1)
				conn.SetWriteObserver(func(packet.Packet) func() { return func() { sent <- struct{}{} } })
				written := make(chan error, 1)
				if delay > 0 {
					if err := conn.WritePacketDirect(testPacket(700)); err != nil {
						t.Fatal(err)
					}
					go func() { written <- conn.SetSendDelay(0) }()
				} else {
					go func() { written <- conn.WritePacketDirect(testPacket(700)) }()
				}
				select {
				case <-transport.started:
				case <-time.After(time.Second):
					t.Fatal("transport write did not start")
				}
				closed := make(chan error, 1)
				go func() {
					switch closePath {
					case "abortThenClose":
						_ = conn.Abort()
						closed <- conn.Close()
					case "abort":
						_ = conn.abort(net.ErrClosed)
						closed <- nil
					case "canceledContext":
						conn.cancelFunc(net.ErrClosed)
						closed <- conn.Close()
					}
				}()
				select {
				case err := <-closed:
					if closePath != "abort" && !errors.Is(err, net.ErrClosed) {
						t.Errorf("canceled Close = %v, want net.ErrClosed", err)
					}
				case <-time.After(time.Second):
					transport.unblock()
					<-written
					t.Fatal("canceled close waited for the transport write")
				}
				transport.unblock()
				if err := <-written; !errors.Is(err, net.ErrClosed) {
					t.Fatalf("write after canceled close = %v, want net.ErrClosed", err)
				}
				select {
				case <-sent:
					t.Fatal("canceled close allowed a delivery completion")
				default:
				}
			})
		}
	}
}
