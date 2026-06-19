package internal

import (
	"sync"

	"github.com/df-mc/go-nethernet"
)

// NewNotifier returns a Notifier that is ready for use.
func NewNotifier() *Notifier {
	return &Notifier{
		notifiers: make(map[uint32]nethernet.Notifier),
	}
}

// Notifier distributes incoming [nethernet.Signal] values to registered
// signal notifiers.
type Notifier struct {
	notifiers   map[uint32]nethernet.Notifier
	notifyCount uint32
	mu          sync.RWMutex
}

// Notify registers notifier for incoming signals and returns a stop function
// that unregisters it.
func (n *Notifier) Notify(notifier nethernet.Notifier) func() {
	if notifier == nil {
		panic("signaling: nil Notifier")
	}
	n.mu.Lock()
	i := n.notifyCount
	n.notifyCount++
	n.notifiers[i] = notifier
	n.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			n.mu.Lock()
			delete(n.notifiers, i)
			n.mu.Unlock()
		})
	}
}

// Signal sends signal to all registered notifiers.
func (n *Notifier) Signal(signal *nethernet.Signal) {
	n.mu.RLock()
	notifiers := make([]nethernet.Notifier, 0, len(n.notifiers))
	for _, notifier := range n.notifiers {
		notifiers = append(notifiers, notifier)
	}
	n.mu.RUnlock()

	for _, notifier := range notifiers {
		notifier.NotifySignal(signal)
	}
}

// Close unregisters all notifiers.
func (n *Notifier) Close() {
	n.mu.Lock()
	clear(n.notifiers)
	n.mu.Unlock()
}
