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
	ch   chan<- *nethernet.Signal
	done chan struct{}
	once sync.Once

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

// Register adds signals to the set of channels notified by [Notifier.Notify]
// and returns a stop function that removes and closes the channel. The caller
// must not close the channel themselves.
func (n *Notifier) Register(signals chan<- *nethernet.Signal) (stop func()) {
	n.mu.Lock()
	i := n.notifyCount
	n.notifyCount++
	n.notifiers[i] = &notifier{ch: signals, done: make(chan struct{})}
	n.mu.Unlock()

	return func() {
		n.mu.Lock()
		entry := n.stop(i)
		n.mu.Unlock()
		if entry != nil {
			entry.close()
		}
	}
}

// Signal sends signal to all registered channels. If a channel is not ready
// to receive, the signal is dropped for that channel and a debug message is
// logged.
func (n *Notifier) Signal(signal *nethernet.Signal) {
	for _, entry := range n.snapshot() {
		if !entry.acquire() {
			continue
		}
		select {
		case entry.ch <- signal:
		case <-entry.done:
		default:
			n.log.Debug("dropping signal due to notifier being backed up", slog.String("signal", signal.String()))
		}
		entry.release()
	}
}

// SignalContext sends signal to all registered channels, blocking until each
// channel receives the signal or ctx is done. It returns ctx.Err if delivery
// is interrupted by context cancellation.
func (n *Notifier) SignalContext(ctx context.Context, signal *nethernet.Signal) error {
	for _, entry := range n.snapshot() {
		if !entry.acquire() {
			continue
		}
		select {
		case entry.ch <- signal:
			entry.release()
		case <-entry.done:
			entry.release()
		case <-ctx.Done():
			entry.release()
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
func (n *Notifier) stop(i uint32) *notifier {
	entry, ok := n.notifiers[i]
	if !ok {
		return nil
	}
	delete(n.notifiers, i)
	return entry
}

// Close unregisters and closes all registered channels.
func (n *Notifier) Close() error {
	n.mu.Lock()
	entries := make([]*notifier, 0, len(n.notifiers))
	for i := range n.notifiers {
		entries = append(entries, n.stop(i))
	}
	n.mu.Unlock()

	for _, entry := range entries {
		entry.close()
	}
	return nil
}

func (n *notifier) acquire() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return false
	}
	n.wg.Add(1)
	return true
}

func (n *notifier) release() {
	n.wg.Done()
}

func (n *notifier) close() {
	n.once.Do(func() {
		n.mu.Lock()
		n.closed = true
		close(n.done)
		n.mu.Unlock()
		n.wg.Wait()
		close(n.ch)
	})
}
