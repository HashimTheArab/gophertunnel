package internal

import (
	"context"
	"log/slog"
	"sync"

	"github.com/df-mc/go-nethernet"
)

// NewNotifier returns a Notifier that is ready for use. The given logger is
// used to log a debug message when a signal is dropped because a registered
// channel is full.
func NewNotifier(log *slog.Logger) *Notifier {
	return &Notifier{
		notifiers: make(map[uint32]*notifier),
		log:       log,
	}
}

// Notifier distributes incoming [nethernet.Signal] values to a set of
// channels registered with [Notifier.Register].
type Notifier struct {
	notifiers   map[uint32]*notifier
	notifyCount uint32
	mu          sync.RWMutex
	log         *slog.Logger
}

type notifier struct {
	ch     chan<- *nethernet.Signal
	mu     sync.Mutex
	closed bool
}

// Register adds signals to the set of channels notified by [Notifier.Notify]
// and returns a stop function that removes and closes the channel. The caller
// must not close the channel themselves.
func (n *Notifier) Register(signals chan<- *nethernet.Signal) (stop func()) {
	n.mu.Lock()
	i := n.notifyCount
	n.notifyCount++
	n.notifiers[i] = &notifier{ch: signals}
	n.mu.Unlock()

	return func() {
		n.mu.Lock()
		n.stop(i)
		n.mu.Unlock()
	}
}

// Signal sends signal to all registered channels. If a channel is not ready
// to receive, the signal is dropped for that channel and a debug message is
// logged.
func (n *Notifier) Signal(signal *nethernet.Signal) {
	for _, entry := range n.snapshot() {
		entry.mu.Lock()
		if entry.closed {
			entry.mu.Unlock()
			continue
		}
		select {
		case entry.ch <- signal:
		default:
			n.log.Debug("dropping signal due to notifier being backed up", slog.String("signal", signal.String()))
		}
		entry.mu.Unlock()
	}
}

// SignalContext sends signal to all registered channels, blocking until each
// channel receives the signal or ctx is done. It returns ctx.Err if delivery
// is interrupted by context cancellation.
func (n *Notifier) SignalContext(ctx context.Context, signal *nethernet.Signal) error {
	for _, entry := range n.snapshot() {
		entry.mu.Lock()
		if entry.closed {
			entry.mu.Unlock()
			continue
		}
		select {
		case entry.ch <- signal:
			entry.mu.Unlock()
		case <-ctx.Done():
			entry.mu.Unlock()
			return ctx.Err()
		}
	}
	return nil
}

func (n *Notifier) snapshot() []*notifier {
	n.mu.RLock()
	entries := make([]*notifier, 0, len(n.notifiers))
	for _, entry := range n.notifiers {
		entries = append(entries, entry)
	}
	n.mu.RUnlock()
	return entries
}

// stop removes the channel registered with the given ID and closes it.
// The caller must hold mu before calling stop.
func (n *Notifier) stop(i uint32) {
	entry, ok := n.notifiers[i]
	if !ok {
		return
	}
	delete(n.notifiers, i)
	entry.mu.Lock()
	if !entry.closed {
		entry.closed = true
		close(entry.ch)
	}
	entry.mu.Unlock()
}

// Close unregisters and closes all registered channels.
func (n *Notifier) Close() error {
	n.mu.Lock()
	for i := range n.notifiers {
		n.stop(i)
	}
	n.mu.Unlock()

	return nil
}
