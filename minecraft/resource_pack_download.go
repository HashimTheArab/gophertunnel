package minecraft

import (
	"fmt"
	"sync"
)

// DefaultResourcePackMaxInFlightChunks matches the vanilla client request window.
const DefaultResourcePackMaxInFlightChunks = 100

// DefaultResourcePackMaxBytes limits a single downloaded archive to 512 MiB.
const DefaultResourcePackMaxBytes = 512 << 20

// DefaultResourcePackDownloadBudgetBytes limits live download files across dialers to 2 GiB.
const DefaultResourcePackDownloadBudgetBytes = 2 << 30

var defaultResourcePackDownloadBudget = NewResourcePackDownloadBudget(DefaultResourcePackDownloadBudgetBytes)

// ResourcePackDownloadConfig controls resource pack downloads performed by a Dialer.
type ResourcePackDownloadConfig struct {
	// MaxInFlightChunks is the maximum number of outstanding chunk requests. Values below one use the
	// vanilla default.
	MaxInFlightChunks int
	// MaxPackBytes limits each archive, including a nested archive after extraction. Zero uses
	// DefaultResourcePackMaxBytes. Both advertised sizes and subsequent size changes are checked.
	MaxPackBytes uint64
	// Budget bounds the total size reserved for downloaded files until their connections close.
	// Share one budget across dialers using the same storage. Nil uses a process-wide budget of
	// DefaultResourcePackDownloadBudgetBytes. Cached entries are bounded separately by the cache.
	Budget *ResourcePackDownloadBudget
}

// normalized returns the configuration with defaults filled in.
func (config ResourcePackDownloadConfig) normalized() ResourcePackDownloadConfig {
	if config.MaxInFlightChunks < 1 {
		config.MaxInFlightChunks = DefaultResourcePackMaxInFlightChunks
	}
	if config.MaxPackBytes == 0 {
		config.MaxPackBytes = DefaultResourcePackMaxBytes
	}
	if config.Budget == nil {
		config.Budget = defaultResourcePackDownloadBudget
	}
	return config
}

// validateSize rejects archives that exceed the configured limit or cannot be represented by Pack.Size.
func (config ResourcePackDownloadConfig) validateSize(size uint64) error {
	if size > config.MaxPackBytes {
		return fmt.Errorf("resource pack size %d exceeds limit %d", size, config.MaxPackBytes)
	}
	if size > uint64(^uint(0)>>1) {
		return fmt.Errorf("resource pack size %d exceeds supported limit", size)
	}
	return nil
}

// ResourcePackDownloadBudget bounds live download archives across connections. A reservation remains
// held while the connection serves the file, and is released when the file is removed. It is safe for
// concurrent use and must not be copied. The zero value uses the default limit. This is independent of
// the completed cache's size limit.
type ResourcePackDownloadBudget struct {
	mu       sync.Mutex
	maxBytes uint64
	used     uint64
}

// NewResourcePackDownloadBudget creates a shared download budget. Zero uses the default limit.
func NewResourcePackDownloadBudget(maxBytes uint64) *ResourcePackDownloadBudget {
	if maxBytes == 0 {
		maxBytes = DefaultResourcePackDownloadBudgetBytes
	}
	return &ResourcePackDownloadBudget{maxBytes: maxBytes}
}

// reserve claims space before a file is created or allowed to grow.
func (budget *ResourcePackDownloadBudget) reserve(size uint64) error {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.maxBytes == 0 {
		budget.maxBytes = DefaultResourcePackDownloadBudgetBytes
	}
	if size > budget.maxBytes-budget.used {
		return fmt.Errorf("resource pack download budget exhausted: need %d bytes, %d available", size, budget.maxBytes-budget.used)
	}
	budget.used += size
	return nil
}

// release returns the reservation after its file has been removed or shrunk.
func (budget *ResourcePackDownloadBudget) release(size uint64) {
	budget.mu.Lock()
	budget.used -= size
	budget.mu.Unlock()
}
