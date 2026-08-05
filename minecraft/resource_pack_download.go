package minecraft

// DefaultResourcePackMaxInFlightChunks matches the vanilla client request window.
const DefaultResourcePackMaxInFlightChunks = 100

// ResourcePackDownloadConfig controls resource pack downloads performed by a Dialer.
type ResourcePackDownloadConfig struct {
	// MaxInFlightChunks is the maximum number of outstanding chunk requests. Values below one use the
	// vanilla default.
	MaxInFlightChunks int
}

func resolveResourcePackDownloadConfig(config ResourcePackDownloadConfig) ResourcePackDownloadConfig {
	if config.MaxInFlightChunks < 1 {
		config.MaxInFlightChunks = DefaultResourcePackMaxInFlightChunks
	}
	return config
}
