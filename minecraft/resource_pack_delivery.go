package minecraft

import "time"

const (
	// DefaultResourcePackChunkSize is the size of a resource pack chunk sent by a
	// Listener when no delivery configuration is provided.
	DefaultResourcePackChunkSize uint32 = 128 * 1024
	// DefaultResourcePackChunkSendDelay spaces resource pack chunks sent by a
	// Listener. It keeps the safe default for clients that cannot process a
	// faster transfer reliably.
	DefaultResourcePackChunkSendDelay = 200 * time.Millisecond
)

// ResourcePackDeliveryConfig controls how a Listener sends resource pack data
// to connected clients.
//
// A nil configuration keeps the conservative defaults used by gophertunnel.
// ChunkSize set to zero uses DefaultResourcePackChunkSize. ChunkSendDelay set
// to zero explicitly disables pacing; a negative delay is also treated as
// zero.
type ResourcePackDeliveryConfig struct {
	// ChunkSize is the size in bytes of each ResourcePackChunkData payload.
	ChunkSize uint32
	// ChunkSendDelay is the delay after each ResourcePackChunkData packet.
	ChunkSendDelay time.Duration
}

func defaultResourcePackDeliveryConfig() ResourcePackDeliveryConfig {
	return ResourcePackDeliveryConfig{
		ChunkSize:      DefaultResourcePackChunkSize,
		ChunkSendDelay: DefaultResourcePackChunkSendDelay,
	}
}

func resolveResourcePackDeliveryConfig(config *ResourcePackDeliveryConfig) ResourcePackDeliveryConfig {
	if config == nil {
		return defaultResourcePackDeliveryConfig()
	}
	delivery := *config
	if delivery.ChunkSize == 0 {
		delivery.ChunkSize = DefaultResourcePackChunkSize
	}
	if delivery.ChunkSendDelay < 0 {
		delivery.ChunkSendDelay = 0
	}
	return delivery
}
