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
		notifiers: make(map[uint32]chan *nethernet.Signal),
		log:       log,
	}
}

// Notifier distributes incoming [nethernet.Signal] values to registered
// subscription channels.
type Notifier struct {
	notifiers   map[uint32]chan *nethernet.Signal
	notifyCount uint32
	mu          sync.RWMutex
	log         *slog.Logger
}

// Register returns a channel that receives incoming signals. The returned stop
// function removes and closes the channel.
func (n *Notifier) Register() (<-chan *nethernet.Signal, func()) {
	signals := make(chan *nethernet.Signal, 64)

	n.mu.Lock()
	i := n.notifyCount
	n.notifyCount++
	n.notifiers[i] = signals
	n.mu.Unlock()

	return signals, func() {
		n.mu.Lock()
		n.stop(i)
		n.mu.Unlock()
	}
}

// Signal sends signal to all registered channels. If a channel is not ready
// to receive, the signal is dropped for that channel and a debug message is
// logged.
func (n *Notifier) Signal(signal *nethernet.Signal) {
	n.mu.RLock()
	for _, ch := range n.notifiers {
		select {
		case ch <- signal:
		default:
			n.log.Debug("dropping signal due to notifier being backed up", slog.String("signal", signal.String()))
		}
	}
	n.mu.RUnlock()
}

// SignalContext sends signal to all registered channels, blocking until each
// channel accepts the signal or ctx is canceled.
func (n *Notifier) SignalContext(ctx context.Context, signal *nethernet.Signal) error {
	if ctx == nil {
		ctx = context.Background()
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	for _, ch := range n.notifiers {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ch <- signal:
		}
	}
	return nil
}

// stop removes the channel registered with the given ID and closes it.
// The caller must hold mu before calling stop.
func (n *Notifier) stop(i uint32) {
	ch, ok := n.notifiers[i]
	if !ok {
		return
	}
	delete(n.notifiers, i)
	close(ch)
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
