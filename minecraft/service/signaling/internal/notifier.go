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

type notifier struct {
	ch   chan<- *nethernet.Signal
	done chan struct{}
}

// Notifier distributes incoming [nethernet.Signal] values to a set of
// channels registered with [Notifier.Register].
type Notifier struct {
	notifiers   map[uint32]*notifier
	notifyCount uint32
	mu          sync.RWMutex
	log         *slog.Logger
}

// Register adds signals to the set of channels notified by [Notifier.Notify]
// and returns a stop function that removes it. The caller owns the channel
// lifetime.
func (n *Notifier) Register(signals chan<- *nethernet.Signal) (stop func()) {
	n.mu.Lock()
	i := n.notifyCount
	n.notifyCount++
	n.notifiers[i] = &notifier{ch: signals, done: make(chan struct{})}
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
	for _, notify := range n.snapshot() {
		select {
		case <-notify.done:
		case notify.ch <- signal:
		default:
			n.log.Debug("dropping signal due to notifier being backed up", slog.String("signal", signal.String()))
		}
	}
}

// SignalContext sends signal to all registered channels, blocking until each
// active channel receives the signal, is stopped, or ctx is done. It returns
// ctx.Err if delivery is interrupted by context cancellation.
func (n *Notifier) SignalContext(ctx context.Context, signal *nethernet.Signal) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for _, notify := range n.snapshot() {
		select {
		case <-notify.done:
		case notify.ch <- signal:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (n *Notifier) snapshot() []*notifier {
	n.mu.RLock()
	defer n.mu.RUnlock()
	notifiers := make([]*notifier, 0, len(n.notifiers))
	for _, notify := range n.notifiers {
		notifiers = append(notifiers, notify)
	}
	return notifiers
}

// stop removes the channel registered with the given ID.
// The caller must hold mu before calling stop.
func (n *Notifier) stop(i uint32) {
	notify, ok := n.notifiers[i]
	if !ok {
		return
	}
	delete(n.notifiers, i)
	close(notify.done)
}

// Close unregisters all registered channels.
func (n *Notifier) Close() error {
	n.mu.Lock()
	for i := range n.notifiers {
		n.stop(i)
	}
	n.mu.Unlock()

	return nil
}
