package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// SubChunk sends data about multiple sub-chunks around a center point.
type SubChunk struct {
	// CacheEnabled is whether the sub-chunk caching is enabled or not.
	CacheEnabled  bool
	DimensionType protocol.DimensionType
	// Position is an absolute sub-chunk center point that every SubChunkRequest uses as a reference.
	CenterPos protocol.SubChunkPos
	// SubChunkEntries contains sub-chunk entries relative to the center point.
	SubChunkData []protocol.SubChunkData
}

// ID ...
func (*SubChunk) ID() uint32 {
	return IDSubChunk
}

func (pk *SubChunk) Marshal(io protocol.IO) {
	io.Bool(&pk.CacheEnabled)
	pk.DimensionType.Marshal(io)
	pk.CenterPos.Marshal(io)
	protocol.SliceLimits(io, &pk.SubChunkData, 0, 8192)
}
