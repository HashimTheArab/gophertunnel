package messaging

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/creachadair/jrpc2"
	"github.com/df-mc/go-nethernet"
	"github.com/google/uuid"
)

func TestConnHandleInnerMessageDoesNotAcknowledgeRejectedSignal(t *testing.T) {
	signal := &nethernet.Signal{
		Type:         nethernet.SignalTypeOffer,
		ConnectionID: 42,
		Data:         "offer",
	}
	params, err := json.Marshal(map[string]any{
		"netherNetId": "network",
		"message":     signal.String(),
	})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	conn := &Conn{
		d:         Dialer{Log: slog.New(slog.NewTextHandler(io.Discard, nil))},
		notifiers: make(map[uint32]nethernet.Notifier),
	}
	err = conn.handleInnerMessage(context.Background(), &envelope{
		From: uuid.New(),
		ID:   uuid.New(),
		Message: &jrpc2.ParsedRequest{
			Method: MethodSignalingWebRTC,
			Params: params,
		},
	})
	if !errors.Is(err, errSignalNotAccepted) {
		t.Fatalf("handleInnerMessage() error = %v, want %v", err, errSignalNotAccepted)
	}
}
