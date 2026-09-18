package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// JigsawStructureData is sent by the server to let the client know all the rules for jigsaw structures.
type JigsawStructureData struct {
	JigsawStructureDataTag []byte
}

// ID returns the protocol ID for JigsawStructureData.
func (*JigsawStructureData) ID() uint32 { return IDJigsawStructureData }

// Marshal reads or writes JigsawStructureData using its canonical wire layout.
func (pk *JigsawStructureData) Marshal(io protocol.IO) {
	io.NBT(&pk.JigsawStructureDataTag, protocol.NBTNetwork)
}
