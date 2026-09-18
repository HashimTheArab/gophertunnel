package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// JigsawStructureData is sent by the server to let the client know all the rules for jigsaw structures.
type JigsawStructureData struct {
	JigsawStructureDataTag []byte
}

// ID ...
func (*JigsawStructureData) ID() uint32 {
	return IDJigsawStructureData
}

func (pk *JigsawStructureData) Marshal(io protocol.IO) {
	io.NBT(&pk.JigsawStructureDataTag, protocol.NBTNetwork)
}
