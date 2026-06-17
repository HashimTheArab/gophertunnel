package signaling

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/df-mc/go-nethernet"
	"github.com/sandertv/gophertunnel/minecraft/service/signaling/internal"
)

func TestSignalUsesCallerContextForWrite(t *testing.T) {
	conn := newTestConn(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := conn.Signal(ctx, &nethernet.Signal{
		Type:         nethernet.SignalTypeCandidate,
		ConnectionID: 1,
		NetworkID:    "remote-network",
		Data:         "candidate",
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Signal() error = %v, want context.Canceled", err)
	}
}

func TestMessageTypeErrorWithoutIDStopsConn(t *testing.T) {
	conn := newTestConn(t)
	conn.handleMessage(Message{
		Type: MessageTypeError,
		Data: `{"Code":2,"Message":"delivery failed"}`,
	})

	select {
	case <-conn.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("connection context was not canceled")
	}
	var signalingErr *Error
	if !errors.As(context.Cause(conn.ctx), &signalingErr) {
		t.Fatalf("context cause = %v, want *Error", context.Cause(conn.ctx))
	}
	if signalingErr.Code != ErrorCodeDeliveryFailure {
		t.Fatalf("error code = %v, want %v", signalingErr.Code, ErrorCodeDeliveryFailure)
	}
}

func newTestConn(t *testing.T) *Conn {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		for {
			if _, _, err := c.Read(r.Context()); err != nil {
				return
			}
		}
	}))
	t.Cleanup(func() {
		server.Close()
	})

	c, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	conn := &Conn{
		conn:                c,
		d:                   Dialer{Log: slog.Default()},
		credentialsReceived: make(chan struct{}),
		notifier:            internal.NewNotifier(slog.Default()),
		pending:             internal.NewPendingMap(),
	}
	conn.ctx, conn.cancel = context.WithCancelCause(context.Background())
	t.Cleanup(func() {
		conn.cancel(net.ErrClosed)
		_ = conn.notifier.Close()
		_ = conn.conn.CloseNow()
	})
	return conn
}
