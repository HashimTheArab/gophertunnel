package minecraft

import (
	"errors"
	"net"
	"testing"
)

type closedListener struct{ NetworkListener }

func (closedListener) Close() error   { return nil }
func (closedListener) Addr() net.Addr { return &net.UDPAddr{} }

// A connection that finishes logging in as the listener shuts down must be
// turned away, not panic on a closed channel; Accept must report the close.
func TestDeliverAfterShutdown(t *testing.T) {
	l := &Listener{incoming: make(chan *Conn), close: make(chan struct{}), listener: closedListener{}}
	l.shutdown()
	for i := 0; i < 10000; i++ {
		if l.deliverConn(&Conn{}) {
			t.Fatal("a connection was delivered to a closed listener")
		}
	}
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after shutdown: %v, want net.ErrClosed", err)
	}
}
