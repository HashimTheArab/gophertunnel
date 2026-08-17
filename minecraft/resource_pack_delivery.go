package minecraft

// DefaultResourcePackChunkSize is the size of a single chunk of data from a resource pack sent by a
// Listener: 128 KiB.
const DefaultResourcePackChunkSize = 1024 * 128

// ResourcePackDeliveryConfig controls how a Listener sends resource pack data to clients. The zero value
// uses the default chunk size.
type ResourcePackDeliveryConfig struct {
	// ChunkSize is the size of each ResourcePackChunkData payload. Zero uses DefaultResourcePackChunkSize.
	ChunkSize uint32
}

// defaultResourcePackDeliveryConfig returns the default resource pack delivery configuration.
func defaultResourcePackDeliveryConfig() ResourcePackDeliveryConfig {
	return ResourcePackDeliveryConfig{ChunkSize: DefaultResourcePackChunkSize}
}

// normalized returns the configuration with defaults filled in.
func (config ResourcePackDeliveryConfig) normalized() ResourcePackDeliveryConfig {
	if config.ChunkSize == 0 {
		config.ChunkSize = defaultResourcePackDeliveryConfig().ChunkSize
	}
	return config
}
