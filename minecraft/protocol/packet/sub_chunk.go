package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// SubChunk sends data about multiple sub-chunks around a center point.
type SubChunk struct {
	// CacheEnabled is whether the sub-chunk caching is enabled or not.
	CacheEnabled  bool
	DimensionType protocol.DimensionType
	CenterPos     protocol.SubChunkPos
	SubChunkData  []protocol.SubChunkData
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
