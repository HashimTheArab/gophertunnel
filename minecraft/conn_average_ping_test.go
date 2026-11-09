package minecraft

import (
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/internal"
)

// pingConn is a net.Conn whose transport reports a fixed average ping.
type pingConn struct {
	net.Conn
	ping time.Duration
	ok   bool
}

// AveragePing returns the fixed ping the test configured.
func (c pingConn) AveragePing() (time.Duration, bool) { return c.ping, c.ok }

// newAveragePingConn wraps netConn in a manually flushed Conn that is closed with the test.
func newAveragePingConn(t *testing.T, netConn net.Conn) *Conn {
	t.Helper()
	conn := newConn(netConn, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestAveragePingForwardsTransportMeasurement(t *testing.T) {
	client, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	conn := newAveragePingConn(t, pingConn{Conn: client, ping: 31 * time.Millisecond, ok: true})
	if got, ok := conn.AveragePing(); !ok || got != 31*time.Millisecond {
		t.Fatalf("AveragePing() = %v, %v, want 31ms, true", got, ok)
	}
}

func TestAveragePingUnknownWithoutTransportSupport(t *testing.T) {
	client, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	conn := newAveragePingConn(t, client)
	if got, ok := conn.AveragePing(); ok {
		t.Fatalf("AveragePing() = %v, true for a transport without ping measurement", got)
	}
}
