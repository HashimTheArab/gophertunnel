package signaling

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/df-mc/go-nethernet"
)

// recordingNotifier records calls and returns a fixed acceptance result.
type recordingNotifier struct {
	accept bool
	calls  int
}

// NotifySignal records the signal and returns the configured result.
func (n *recordingNotifier) NotifySignal(*nethernet.Signal) bool {
	n.calls++
	return n.accept
}

func TestConnHandleMessageLogsRejectedSignalWithoutPayload(t *testing.T) {
	var logs bytes.Buffer
	conn := &Conn{
		d: Dialer{Log: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))},
		notifiers: make(map[uint32]nethernet.Notifier),
	}
	signal := &nethernet.Signal{
		Type:         "remote-controlled-type",
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
	if strings.Contains(logs.String(), signal.Type) {
		t.Fatal("rejected signal log contains the remote-controlled signal type")
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

func TestConnNotifySignalReportsCollectiveAcceptance(t *testing.T) {
	reject := &recordingNotifier{}
	accept := &recordingNotifier{accept: true}
	conn := &Conn{notifiers: map[uint32]nethernet.Notifier{0: reject, 1: accept}}

	if !conn.notifySignal(new(nethernet.Signal)) {
		t.Fatal("notifySignal() = false, want true")
	}
	if reject.calls != 1 || accept.calls != 1 {
		t.Fatalf("notifier calls = (%d, %d), want (1, 1)", reject.calls, accept.calls)
	}
}
