package minecraft

import (
	"fmt"
	"math"
	"sync"

	"github.com/sandertv/gophertunnel/minecraft/resource"
)

// ResourcePackChunkWindow schedules a bounded resource-pack download without
// retaining its contents. Accept validates incoming chunks; Consumed releases
// their request slots after the caller has processed them. Methods are safe to
// call concurrently.
type ResourcePackChunkWindow struct {
	mu                               sync.Mutex
	size                             uint64
	chunkSize, count, next, consumed uint32
	limit                            int
	pending                          map[uint32]bool
}

// NewResourcePackChunkWindow uses the advertised size and chunk size rather than
// trusting the server's advertised chunk count.
func NewResourcePackChunkWindow(size uint64, chunkSize uint32, config ResourcePackDownloadConfig) (*ResourcePackChunkWindow, error) {
	if chunkSize == 0 {
		return nil, fmt.Errorf("zero resource pack chunk size")
	}
	count, ok := resource.ChunkCount(size, chunkSize)
	if !ok || uint64(count) > uint64(math.MaxInt32)+1 {
		return nil, fmt.Errorf("too many resource pack chunks")
	}
	limit := config.normalized().MaxInFlightChunks
	if uint64(limit) > uint64(count) {
		limit = max(int(count), 1)
	}
	return &ResourcePackChunkWindow{size: size, chunkSize: chunkSize, count: count, limit: limit, pending: map[uint32]bool{}}, nil
}

// ChunkCount returns the number of chunks required for the complete pack.
func (w *ResourcePackChunkWindow) ChunkCount() uint32 { return w.count }

// Capacity returns the maximum number of requested or buffered chunks.
func (w *ResourcePackChunkWindow) Capacity() int { return w.limit }

// Requests reserves the next request indices up to the window capacity. A failed
// write must abandon the download rather than reuse these reserved indices.
func (w *ResourcePackChunkWindow) Requests() []uint32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	var requests []uint32
	for w.next < w.count && len(w.pending) < w.limit {
		requests = append(requests, w.next)
		w.pending[w.next] = false
		w.next++
	}
	return requests
}

// Accept validates one requested chunk without releasing its buffer slot.
// Invalid or duplicate chunks do not alter the window.
func (w *ResourcePackChunkWindow) Accept(index uint32, length int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if index >= w.count {
		return fmt.Errorf("chunk index %d exceeds resource pack chunk count %d", index, w.count)
	}
	expected := min(w.size-uint64(index)*uint64(w.chunkSize), uint64(w.chunkSize))
	if length < 0 || uint64(length) != expected {
		return fmt.Errorf("expected chunk size %d, got %d", expected, length)
	}
	received, requested := w.pending[index]
	if !requested || received {
		return fmt.Errorf("resource pack chunk %d was not requested or was already received", index)
	}
	w.pending[index] = true
	return nil
}

// Consumed releases an accepted chunk after its contents have been processed.
func (w *ResourcePackChunkWindow) Consumed(index uint32) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.pending[index] {
		return fmt.Errorf("resource pack chunk %d was not accepted", index)
	}
	delete(w.pending, index)
	w.consumed++
	return nil
}

// Done reports whether every chunk has been accepted and consumed.
func (w *ResourcePackChunkWindow) Done() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.consumed == w.count
}
