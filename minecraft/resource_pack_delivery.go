package minecraft

import "time"

const (
	// DefaultResourcePackChunkSize is the size of a single chunk of data from a resource pack sent by a
	// Listener: 128 KiB.
	DefaultResourcePackChunkSize = 1024 * 128
	// DefaultResourcePackChunkSendDelay is the default delay between ResourcePackChunkData packets. Resource
	// pack chunks are not paced by default.
	DefaultResourcePackChunkSendDelay time.Duration = 0
)

// ResourcePackDeliveryConfig controls how a Listener sends resource pack data to clients. The zero value
// uses the default chunk size without pacing.
type ResourcePackDeliveryConfig struct {
	// ChunkSize is the size of each ResourcePackChunkData payload. Zero uses DefaultResourcePackChunkSize.
	ChunkSize uint32
	// ChunkSendDelay is the optional delay after each ResourcePackChunkData packet. Values below one disable
	// pacing.
	ChunkSendDelay time.Duration
}

// defaultResourcePackDeliveryConfig returns the default resource pack delivery configuration.
func defaultResourcePackDeliveryConfig() ResourcePackDeliveryConfig {
	return ResourcePackDeliveryConfig{
		ChunkSize:      DefaultResourcePackChunkSize,
		ChunkSendDelay: DefaultResourcePackChunkSendDelay,
	}
}

// normalized returns the configuration with defaults filled in.
func (config ResourcePackDeliveryConfig) normalized() ResourcePackDeliveryConfig {
	defaults := defaultResourcePackDeliveryConfig()
	if config.ChunkSize == 0 {
		config.ChunkSize = defaults.ChunkSize
	}
	if config.ChunkSendDelay < 0 {
		config.ChunkSendDelay = 0
	}
	return config
}
