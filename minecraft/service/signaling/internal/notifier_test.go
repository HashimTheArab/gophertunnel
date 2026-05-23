package internal

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/df-mc/go-nethernet"
)

func TestNotifierSignalContextWaitsForReceiver(t *testing.T) {
	n := NewNotifier(slog.Default())
	ch := make(chan *nethernet.Signal)
	stop := n.Register(ch)
	defer stop()

	signal := &nethernet.Signal{NetworkID: "remote", Type: nethernet.SignalTypeOffer}
	errCh := make(chan error, 1)
	go func() {
		errCh <- n.SignalContext(context.Background(), signal)
	}()

	select {
	case err := <-errCh:
		t.Fatalf("SignalContext returned before receiver accepted signal: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	select {
	case got := <-ch:
		if got != signal {
			t.Fatalf("received signal = %#v, want %#v", got, signal)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for signal")
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("SignalContext returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for SignalContext")
	}
}

func TestNotifierSignalContextReturnsContextError(t *testing.T) {
	n := NewNotifier(slog.Default())
	ch := make(chan *nethernet.Signal)
	stop := n.Register(ch)
	defer stop()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := n.SignalContext(ctx, &nethernet.Signal{}); err != context.Canceled {
		t.Fatalf("SignalContext error = %v, want %v", err, context.Canceled)
	}
}
