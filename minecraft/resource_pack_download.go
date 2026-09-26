package minecraft

// DefaultResourcePackMaxInFlightChunks matches the vanilla client request window.
const DefaultResourcePackMaxInFlightChunks = 100

// maxResourcePackPrealloc bounds the buffer reserved up front for a pack. The size comes from
// ResourcePacksInfo and is only a claim at that point, so a server would otherwise turn one small packet
// into an allocation of any size it names. Larger packs still grow their buffer as chunks arrive.
const maxResourcePackPrealloc = 32 << 20

// ResourcePackDownloadConfig controls resource pack downloads performed by a Dialer.
type ResourcePackDownloadConfig struct {
	// MaxInFlightChunks is the maximum number of outstanding chunk requests. Values below one use the
	// vanilla default.
	MaxInFlightChunks int
}

// normalized returns the configuration with defaults filled in.
func (config ResourcePackDownloadConfig) normalized() ResourcePackDownloadConfig {
	if config.MaxInFlightChunks < 1 {
		config.MaxInFlightChunks = DefaultResourcePackMaxInFlightChunks
	}
	return config
}
