package minecraft

import "github.com/google/uuid"

// DefaultResourcePackMaxInFlightChunks matches the vanilla client request window.
const DefaultResourcePackMaxInFlightChunks = 100

// maxResourcePackPrealloc bounds the buffer reserved up front for a pack. The size comes from
// ResourcePacksInfo and is only a claim at that point, so a server would otherwise turn one small packet
// into an allocation of any size it names. Larger packs still grow their buffer as chunks arrive.
const maxResourcePackPrealloc = 32 << 20

// ResourcePackSource is where a Dialer obtained, or is obtaining, a resource pack.
type ResourcePackSource uint8

const (
	ResourcePackSourceCache  ResourcePackSource = iota + 1 // the Dialer's ResourcePackCache
	ResourcePackSourceURL                                  // the pack's DownloadURL
	ResourcePackSourceChunks                               // ResourcePackChunkData from the server
)

// ResourcePackEventKind is the step a ResourcePackEvent reports.
type ResourcePackEventKind uint8

const (
	// ResourcePackStarted begins a transfer; Size is the byte count expected.
	ResourcePackStarted ResourcePackEventKind = iota + 1
	// ResourcePackReceived reports Size more bytes of a started transfer.
	ResourcePackReceived
	// ResourcePackFinished ends a transfer, or reports a cache hit of Size bytes with no transfer.
	ResourcePackFinished
	// ResourcePackFailed ends a transfer without the pack; Err says why. A failed URL download falls back to
	// chunks, and a cancelled connection fails its transfers with the connection's cause.
	ResourcePackFailed
)

// ResourcePackEvent reports one step of a Dialer's resource pack acquisition.
type ResourcePackEvent struct {
	Kind    ResourcePackEventKind
	Source  ResourcePackSource
	UUID    uuid.UUID
	Version string
	Size    uint64
	Err     error
}

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
