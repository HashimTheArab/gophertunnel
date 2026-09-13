package minecraft

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/internal"
)

func TestRakNetPingContextUsesUpstreamDialer(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	network := RakNet{
		l: slog.New(internal.DiscardHandler{}),
		UpstreamDialer: upstreamDialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			calls.Add(1)
			if network != "udp" {
				t.Fatalf("network = %q, want udp", network)
			}
			if address != "127.0.0.1:19132" {
				t.Fatalf("address = %q, want 127.0.0.1:19132", address)
			}
			return nil, ctx.Err()
		}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := network.PingContext(ctx, "127.0.0.1:19132")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("PingContext error = %v, want context.Canceled", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream dial calls = %d, want 1", calls.Load())
	}
}

func TestRakNetDialContextUsesUpstreamDialer(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	network := RakNet{
		l: slog.New(internal.DiscardHandler{}),
		UpstreamDialer: upstreamDialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			calls.Add(1)
			if network != "udp" {
				t.Fatalf("network = %q, want udp", network)
			}
			if address != "127.0.0.1:19132" {
				t.Fatalf("address = %q, want 127.0.0.1:19132", address)
			}
			return nil, ctx.Err()
		}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := network.DialContext(ctx, "127.0.0.1:19132")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("DialContext error = %v, want context.Canceled", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream dial calls = %d, want 1", calls.Load())
	}
}

func TestRakNetListenUsesServerID(t *testing.T) {
	const serverID = 123456789

	listener, err := (RakNet{ServerID: serverID}).Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	if got := listener.ID(); got != serverID {
		t.Fatalf("listener ID = %d, want %d", got, serverID)
	}
}

func TestRakNetAppliesMTUCapToDialAndListen(t *testing.T) {
	const maxMTU = 1190
	network := RakNet{MaxMTU: maxMTU}

	if got := network.dialer().MaxMTU; got != maxMTU {
		t.Fatalf("dialer MaxMTU = %d, want %d", got, maxMTU)
	}
	if got := network.listenConfig().MaxMTU; got != maxMTU {
		t.Fatalf("listener MaxMTU = %d, want %d", got, maxMTU)
	}
}

func TestRakNetAppliesPacketListener(t *testing.T) {
	listener := packetListenerStub{}
	network := RakNet{UpstreamPacketListener: listener}
	if _, ok := network.listenConfig().UpstreamPacketListener.(packetListenerStub); !ok {
		t.Fatal("RakNet packet listener was not forwarded")
	}
}

type packetListenerStub struct{}

func (packetListenerStub) ListenPacket(string, string) (net.PacketConn, error) { return nil, nil }

func TestRakNetListenGeneratesServerIDsByDefault(t *testing.T) {
	first, err := (RakNet{}).Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen first: %v", err)
	}
	t.Cleanup(func() { _ = first.Close() })

	second, err := (RakNet{}).Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen second: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })

	if first.ID() == second.ID() {
		t.Fatalf("generated listener IDs are equal: %d", first.ID())
	}
}

func TestRakNetPingContextAllowsNilLogger(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	network := RakNet{
		UpstreamDialer: upstreamDialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			calls.Add(1)
			return nil, ctx.Err()
		}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := network.PingContext(ctx, "127.0.0.1:19132")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("PingContext error = %v, want context.Canceled", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream dial calls = %d, want 1", calls.Load())
	}
}

type upstreamDialerFunc func(context.Context, string, string) (net.Conn, error)

func (f upstreamDialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}
