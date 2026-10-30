package room

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/p2p"
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

// A NetherNet listener advertises the JSON-RPC signaling it was given, and warns that it advertises
// nothing without it.
func TestListenerServerStatusAdvertisesJSONRPCSignaling(t *testing.T) {
	t.Parallel()

	signaling := testJSONRPCSignaling{networkID: "6503399194777609304", pmid: uuid.New()}
	for name, test := range map[string]struct {
		signaling p2p.JSONRPCSignaling
		want      []p2p.Connection
	}{
		"with signaling": {signaling: signaling, want: []p2p.Connection{{
			Type:              p2p.ConnectionTypeSignalingOverJSONRPC,
			NetherNetID:       p2p.NetherNetID(signaling.networkID),
			PlayerMessagingID: signaling.pmid,
		}}},
		"without signaling": {},
	} {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			announcer := &recordingAnnouncer{}
			l := ListenConfig{
				Announcer: announcer,
				Signaling: test.signaling,
				Log:       slog.New(slog.NewTextHandler(&logs, nil)),
			}.Wrap(fakeNetworkListener{addr: &nethernet.Addr{NetworkID: signaling.networkID}})
			if warned := strings.Contains(logs.String(), "advertises no connection"); warned != (test.signaling == nil) {
				t.Fatalf("missing-signaling warning = %v, want %v", warned, test.signaling == nil)
			}

			l.ServerStatus(minecraft.ServerStatus{})
			if got := announcer.status.SupportedConnections; !slices.Equal(got, test.want) {
				t.Fatalf("SupportedConnections = %+v, want %+v", got, test.want)
			}
			if got := announcer.status.TransportLayer; got != p2p.TransportLayerNetherNet {
				t.Fatalf("TransportLayer = %d, want NetherNet", got)
			}
		})
	}
}

type testJSONRPCSignaling struct {
	networkID string
	pmid      uuid.UUID
}

func (s testJSONRPCSignaling) NetworkID() string            { return s.networkID }
func (s testJSONRPCSignaling) PlayerMessagingID() uuid.UUID { return s.pmid }

// recordingAnnouncer keeps the last announced Status.
type recordingAnnouncer struct{ status Status }

func (a *recordingAnnouncer) Announce(_ context.Context, status Status) error {
	a.status = status
	return nil
}
func (*recordingAnnouncer) Close() error { return nil }

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
