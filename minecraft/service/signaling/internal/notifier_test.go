package internal

import (
	"testing"

	"github.com/df-mc/go-nethernet"
)

// testNotifier records calls and returns a fixed acceptance result.
type testNotifier struct {
	accept bool
	calls  int
}

// NotifySignal records the signal delivery and returns the configured result.
func (n *testNotifier) NotifySignal(*nethernet.Signal) bool {
	n.calls++
	return n.accept
}

func TestNotifySignalReportsCollectiveAcceptance(t *testing.T) {
	reject := &testNotifier{}
	accept := &testNotifier{accept: true}

	if NotifySignal(map[uint32]nethernet.Notifier{0: reject}, new(nethernet.Signal)) {
		t.Fatal("NotifySignal(all rejected) = true, want false")
	}
	if !NotifySignal(map[uint32]nethernet.Notifier{0: reject, 1: accept}, new(nethernet.Signal)) {
		t.Fatal("NotifySignal(one accepted) = false, want true")
	}
	if reject.calls != 2 {
		t.Fatalf("rejecting notifier calls = %d, want 2", reject.calls)
	}
	if accept.calls != 1 {
		t.Fatalf("accepting notifier calls = %d, want 1", accept.calls)
	}
}
