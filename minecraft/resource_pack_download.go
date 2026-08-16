package minecraft

// DefaultResourcePackMaxInFlightChunks matches the vanilla client request window.
const DefaultResourcePackMaxInFlightChunks = 100

// ResourcePackDownloadConfig controls resource pack downloads performed by a Dialer.
type ResourcePackDownloadConfig struct {
	// MaxInFlightChunks is the maximum number of outstanding chunk requests. Values below one use the
	// vanilla default.
	MaxInFlightChunks int
}

// resourcePackChunkCount returns the number of chunks needed for size. The boolean is false if chunkSize is
// zero or the resulting indices cannot be represented by ResourcePackChunkRequest.ChunkIndex.
func resourcePackChunkCount(size uint64, chunkSize uint32) (uint32, bool) {
	if chunkSize == 0 {
		return 0, false
	}
	count := size / uint64(chunkSize)
	if size%uint64(chunkSize) != 0 {
		count++
	}
	if count > uint64(1)<<31 {
		return 0, false
	}
	return uint32(count), true
}

func (config ResourcePackDownloadConfig) normalized() ResourcePackDownloadConfig {
	if config.MaxInFlightChunks < 1 {
		config.MaxInFlightChunks = DefaultResourcePackMaxInFlightChunks
	}
	return config
}
