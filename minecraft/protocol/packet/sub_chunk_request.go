package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// SubChunkRequest requests specific sub-chunks from the server using a center point.
type SubChunkRequest struct {
	DimensionType              protocol.DimensionType
	SubChunkPositionOffsetList []protocol.SubChunkPosOffset
	CenterPos                  protocol.SubChunkPos
}

// ID returns the protocol ID for SubChunkRequest.
func (*SubChunkRequest) ID() uint32 { return IDSubChunkRequest }

// Marshal reads or writes SubChunkRequest using its canonical wire layout.
func (pk *SubChunkRequest) Marshal(io protocol.IO) {
	pk.DimensionType.Marshal(io)
	protocol.SliceLimits(io, &pk.SubChunkPositionOffsetList, 0, 8192)
	pk.CenterPos.Marshal(io)
}
