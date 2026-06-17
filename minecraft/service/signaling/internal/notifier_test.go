package internal

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/df-mc/go-nethernet"
)

func TestSignalContextDoesNotBlockRegistrationWhileDelivering(t *testing.T) {
	n := NewNotifier(slog.Default())
	signals := make(chan *nethernet.Signal)
	n.Register(signals)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- n.SignalContext(ctx, &nethernet.Signal{})
	}()

	registered := make(chan struct{})
	go func() {
		stop := n.Register(make(chan *nethernet.Signal, 1))
		stop()
		close(registered)
	}()

	select {
	case <-registered:
	case <-time.After(100 * time.Millisecond):
		cancel()
		<-done
		t.Fatal("Register blocked while SignalContext waited on a receiver")
	}

	cancel()
	<-done
}

func TestCloseUnblocksSignalContext(t *testing.T) {
	n := NewNotifier(slog.Default())
	n.Register(make(chan *nethernet.Signal))

	delivered := make(chan error, 1)
	go func() {
		delivered <- n.SignalContext(context.Background(), &nethernet.Signal{})
	}()
	time.Sleep(10 * time.Millisecond)

	closed := make(chan error, 1)
	go func() {
		closed <- n.Close()
	}()

	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Close blocked while SignalContext waited on a receiver")
	}

	select {
	case <-delivered:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("SignalContext did not return after Close")
	}
}
