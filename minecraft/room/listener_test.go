package room

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft"
)

func TestListenConfigWrapDefaultsLogger(t *testing.T) {
	t.Parallel()

	l := ListenConfig{
		Announcer: noopAnnouncer{},
	}.Wrap(fakeNetworkListener{addr: stringAddr("unsupported")})

	l.ServerStatus(minecraft.ServerStatus{})
}

// A hung announcer must not block the listener's status ticker forever.
func TestListenerServerStatusBoundsAnnounce(t *testing.T) {
	t.Parallel()

	announcer := blockingAnnouncer{err: make(chan error, 1)}
	l := ListenConfig{
		Announcer:       announcer,
		AnnounceTimeout: 10 * time.Millisecond,
	}.Wrap(fakeNetworkListener{addr: stringAddr("unsupported")})

	done := make(chan struct{})
	go func() {
		l.ServerStatus(minecraft.ServerStatus{})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ServerStatus did not return after AnnounceTimeout")
	}
	if err := <-announcer.err; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("announce context error = %v, want %v", err, context.DeadlineExceeded)
	}
}

// Closing the listener must still cancel an in-flight announcement with net.ErrClosed.
func TestListenerCloseCancelsAnnounce(t *testing.T) {
	t.Parallel()

	announcer := blockingAnnouncer{err: make(chan error, 1)}
	l := ListenConfig{
		Announcer:       announcer,
		AnnounceTimeout: time.Hour,
	}.Wrap(fakeNetworkListener{addr: stringAddr("unsupported")})

	go l.ServerStatus(minecraft.ServerStatus{})
	time.Sleep(10 * time.Millisecond)
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case err := <-announcer.err:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("announce context error = %v, want %v", err, net.ErrClosed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not cancel the announcement")
	}
}

type blockingAnnouncer struct{ err chan error }

func (a blockingAnnouncer) Announce(ctx context.Context, _ Status) error {
	<-ctx.Done()
	a.err <- ctx.Err()
	return ctx.Err()
}
func (blockingAnnouncer) Close() error { return nil }

type noopAnnouncer struct{}

func (noopAnnouncer) Announce(context.Context, Status) error { return nil }
func (noopAnnouncer) Close() error                           { return nil }

type fakeNetworkListener struct {
	addr net.Addr
}

func (f fakeNetworkListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (f fakeNetworkListener) Close() error              { return nil }
func (f fakeNetworkListener) Addr() net.Addr            { return f.addr }
func (f fakeNetworkListener) ID() int64                 { return 0 }
func (f fakeNetworkListener) PongData([]byte)           {}

type stringAddr string

func (s stringAddr) Network() string { return string(s) }
func (s stringAddr) String() string  { return string(s) }
