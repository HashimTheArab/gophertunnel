package minecraft

// DefaultResourcePackMaxInFlightChunks keeps resource pack downloads sequential: one chunk request at a
// time, for compatibility with servers that expect it.
const DefaultResourcePackMaxInFlightChunks = 1

// ResourcePackDownloadConfig controls resource pack downloads performed by a Dialer. The zero value keeps
// the sequential default.
type ResourcePackDownloadConfig struct {
	// MaxInFlightChunks is the maximum number of outstanding chunk requests. Values below one use
	// DefaultResourcePackMaxInFlightChunks. Only raise it when the peer handles pipelined requests.
	MaxInFlightChunks int
}

// normalized returns the configuration with defaults filled in.
func (config ResourcePackDownloadConfig) normalized() ResourcePackDownloadConfig {
	if config.MaxInFlightChunks < 1 {
		config.MaxInFlightChunks = DefaultResourcePackMaxInFlightChunks
	}
	return config
}
