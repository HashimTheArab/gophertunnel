package minecraft

const (
	// DefaultResourcePackMaxInFlightChunks keeps resource pack downloads
	// sequential for compatibility with clients and servers that expect one
	// request at a time.
	DefaultResourcePackMaxInFlightChunks = 1
)

// ResourcePackDownloadConfig controls resource pack downloads performed by a
// Dialer.
//
// MaxInFlightChunks is the maximum number of chunk requests that may be
// outstanding at once. A value less than one uses
// DefaultResourcePackMaxInFlightChunks. The default is intentionally
// sequential; callers that control both ends of the connection may opt into a
// larger bounded window.
type ResourcePackDownloadConfig struct {
	MaxInFlightChunks int
}

func resolveResourcePackDownloadConfig(config ResourcePackDownloadConfig) ResourcePackDownloadConfig {
	if config.MaxInFlightChunks < 1 {
		config.MaxInFlightChunks = DefaultResourcePackMaxInFlightChunks
	}
	return config
}
