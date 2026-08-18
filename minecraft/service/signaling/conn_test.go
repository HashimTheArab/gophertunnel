package signaling

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/df-mc/go-nethernet"
)

func TestConnHandleMessageLogsRejectedSignalWithoutPayload(t *testing.T) {
	var logs bytes.Buffer
	conn := &Conn{
		d:         Dialer{Log: slog.New(slog.NewJSONHandler(&logs, nil))},
		notifiers: make(map[uint32]nethernet.Notifier),
	}
	signal := &nethernet.Signal{
		Type:         nethernet.SignalTypeOffer,
		ConnectionID: 42,
		Data:         "sensitive offer payload",
	}
	conn.handleMessage(Message{
		Type: MessageTypeSignal,
		From: "remote",
		Data: signal.String(),
	})

	if strings.Contains(logs.String(), signal.Data) {
		t.Fatal("rejected signal log contains the signal payload")
	}
	var entry map[string]any
	if err := json.NewDecoder(&logs).Decode(&entry); err != nil {
		t.Fatalf("decode log entry: %v", err)
	}
	if got := entry["msg"]; got != "incoming signal was not accepted" {
		t.Fatalf("log message = %v, want incoming signal was not accepted", got)
	}
	if got := entry["connection_id"]; got != float64(signal.ConnectionID) {
		t.Fatalf("connection_id = %v, want %d", got, signal.ConnectionID)
	}
}
