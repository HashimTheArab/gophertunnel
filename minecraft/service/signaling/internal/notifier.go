package internal

import "github.com/df-mc/go-nethernet"

// NotifySignal sends a signal to every notifier and reports whether at least
// one notifier accepted it.
func NotifySignal(notifiers map[uint32]nethernet.Notifier, signal *nethernet.Signal) bool {
	accepted := false
	for _, notifier := range notifiers {
		if notifier.NotifySignal(signal) {
			accepted = true
		}
	}
	return accepted
}
