package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// SubChunkRequest requests specific sub-chunks from the server using a center point.
type SubChunkRequest struct {
	DimensionType protocol.DimensionType
	// Offsets contains all requested offsets around the center point.
	Offsets []protocol.SubChunkPosOffset
	// Position is an absolute sub-chunk center point used as a base point for all sub-chunks requested. The X and
	// Z coordinates represent the chunk coordinates, while the Y coordinate is the absolute sub-chunk index.
	Position protocol.SubChunkPos
}

// ID ...
func (*SubChunkRequest) ID() uint32 {
	return IDSubChunkRequest
}

func (pk *SubChunkRequest) Marshal(io protocol.IO) {
	pk.DimensionType.Marshal(io)
	protocol.SliceLimits(io, &pk.Offsets, 0, 8192)
	pk.Position.Marshal(io)
}
