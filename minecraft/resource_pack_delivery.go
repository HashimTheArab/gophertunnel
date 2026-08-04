package minecraft

import "time"

const (
	// DefaultResourcePackChunkSize is the size of a single chunk of data from a resource pack sent by a
	// Listener: 128 KiB.
	DefaultResourcePackChunkSize = 1024 * 128
	// DefaultResourcePackChunkSendDelay is the delay a Listener leaves between ResourcePackChunkData
	// packets, so slow clients are not flooded while downloading packs. Clients after 1.26.30 may fail
	// resource pack downloads when pack chunks are sent too aggressively.
	DefaultResourcePackChunkSendDelay = 200 * time.Millisecond
)

// ResourcePackDeliveryConfig controls how a Listener sends resource pack data to connected clients. The
// zero value keeps the conservative defaults used by gophertunnel. A controlled local client that can
// handle a faster transfer reliably may opt into larger chunks or no pacing.
type ResourcePackDeliveryConfig struct {
	// ChunkSize is the size in bytes of each ResourcePackChunkData payload. If zero,
	// DefaultResourcePackChunkSize is used.
	ChunkSize uint32
	// ChunkSendDelay is the delay left after sending each ResourcePackChunkData packet. If zero,
	// DefaultResourcePackChunkSendDelay is used. A negative delay disables pacing entirely.
	ChunkSendDelay time.Duration
}

// normalized returns the configuration with zero values replaced by their defaults and a negative
// ChunkSendDelay replaced by no delay.
func (config ResourcePackDeliveryConfig) normalized() ResourcePackDeliveryConfig {
	if config.ChunkSize == 0 {
		config.ChunkSize = DefaultResourcePackChunkSize
	}
	if config.ChunkSendDelay == 0 {
		config.ChunkSendDelay = DefaultResourcePackChunkSendDelay
	} else if config.ChunkSendDelay < 0 {
		config.ChunkSendDelay = 0
	}
	return config
}
