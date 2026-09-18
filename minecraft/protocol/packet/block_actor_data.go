package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// BlockActorData is sent by the server to update data of a block entity client-side, for example the data of
// a chest.
type BlockActorData struct {
	BlockPosition  protocol.BlockPos
	EntityDataTags []byte
}

// ID ...
func (*BlockActorData) ID() uint32 {
	return IDBlockActorData
}

func (pk *BlockActorData) Marshal(io protocol.IO) {
	pk.BlockPosition.Marshal(io)
	io.NBT(&pk.EntityDataTags, protocol.NBTNetwork)
}
