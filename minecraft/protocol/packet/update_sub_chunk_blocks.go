package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// UpdateSubChunkBlocks is essentially just UpdateBlock packet, however for a set of blocks in a sub-chunk.
type UpdateSubChunkBlocks struct {
	// Position is the block position of the sub-chunk being referred to.
	Position      protocol.BlockPos
	BlocksChanged protocol.UpdateSubChunkBlocksChangedInfo
}

// ID ...
func (*UpdateSubChunkBlocks) ID() uint32 {
	return IDUpdateSubChunkBlocks
}

func (pk *UpdateSubChunkBlocks) Marshal(io protocol.IO) {
	pk.Position.Marshal(io)
	pk.BlocksChanged.Marshal(io)
}
