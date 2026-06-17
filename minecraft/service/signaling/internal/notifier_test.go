package internal

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/google/uuid"
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

func TestPendingMapDoneDoesNotBlockOnFullChannel(t *testing.T) {
	pending := NewPendingMap()
	id := uuid.New()
	ch := make(chan error, 1)
	ch <- errors.New("already completed")

	pending.mu.Lock()
	pending.expected[id] = ch
	pending.mu.Unlock()

	done := make(chan bool, 1)
	go func() {
		done <- pending.Done(id, nil)
	}()

	select {
	case ok := <-done:
		if !ok {
			t.Fatal("Done() = false, want true")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Done() blocked on a full completion channel")
	}
}
