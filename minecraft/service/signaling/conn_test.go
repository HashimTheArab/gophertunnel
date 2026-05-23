package signaling

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/sandertv/gophertunnel/minecraft/service/signaling/internal"
)

func newTestConn(t *testing.T) *Conn {
	t.Helper()
	ctx, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(context.Canceled) })
	log := slog.Default()
	return &Conn{
		d:                   Dialer{Log: log},
		ctx:                 ctx,
		cancel:              cancel,
		credentialsReceived: make(chan struct{}),
		notifier:            internal.NewNotifier(log),
		pending:             internal.NewPendingMap(),
	}
}

func TestConnHandleMessageAcceptsCredentialsWithoutMessageID(t *testing.T) {
	conn := newTestConn(t)
	credentials := nethernet.Credentials{ExpirationInSeconds: 60}
	data, err := json.Marshal(credentials)
	if err != nil {
		t.Fatal(err)
	}

	conn.handleMessage(Message{
		Type: MessageTypeCredentials,
		From: "Server",
		Data: string(data),
	})

	select {
	case <-conn.credentialsReceived:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for credentials")
	}
	if got := conn.credentials.Load(); got == nil || got.ExpirationInSeconds != credentials.ExpirationInSeconds {
		t.Fatalf("credentials = %#v, want ExpirationInSeconds %d", got, credentials.ExpirationInSeconds)
	}
}

func TestConnHandleMessageAcceptsSignalWithoutMessageID(t *testing.T) {
	conn := newTestConn(t)
	ch := make(chan *nethernet.Signal, 1)
	stop := conn.Notify(ch)
	defer stop()

	want := &nethernet.Signal{
		Type:         nethernet.SignalTypeOffer,
		ConnectionID: 123,
		Data:         "payload",
	}
	conn.handleMessage(Message{
		Type: MessageTypeSignal,
		From: "remote-network",
		Data: want.String(),
	})

	select {
	case got := <-ch:
		if got.Type != want.Type || got.ConnectionID != want.ConnectionID || got.Data != want.Data || got.NetworkID != "remote-network" {
			t.Fatalf("signal = %#v, want %#v with NetworkID %q", got, want, "remote-network")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for signal")
	}
}
