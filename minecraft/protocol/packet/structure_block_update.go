package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	StructureBlockData    protocol.StructureBlockType = 0
	StructureBlockSave    protocol.StructureBlockType = 1
	StructureBlockLoad    protocol.StructureBlockType = 2
	StructureBlockCorner  protocol.StructureBlockType = 3
	StructureBlockInvalid protocol.StructureBlockType = 4
	StructureBlockExport  protocol.StructureBlockType = 5
)

const (
	StructureRedstoneSaveModeMemory protocol.StructureRedstoneSaveMode = 0
	StructureRedstoneSaveModeDisk   protocol.StructureRedstoneSaveMode = 1
)

// StructureBlockUpdate is sent by the client when it updates a structure block using the in-game UI. The data
// it contains depends on the type of structure block that it is. In Minecraft Bedrock Edition v1.11, there is
// only the Export structure block type, but in v1.13 the ones present in Java Edition will, according to the
// wiki, be added too.
type StructureBlockUpdate struct {
	// Position is the position of the structure block that is updated.
	Position protocol.BlockPos
	// Settings is a struct of settings that should be used for exporting the structure. These settings are
	// identical to the last sent in the StructureBlockUpdate packet by the client.
	Settings protocol.StructureEditorData
	// ShouldTrigger specifies if the structure block should be triggered immediately after this packet reaches
	// the server.
	ShouldTrigger bool
	// Waterlogged specifies if non-air blocks replace water or combine with water.
	Waterlogged bool
}

// ID ...
func (*StructureBlockUpdate) ID() uint32 {
	return IDStructureBlockUpdate
}

func (pk *StructureBlockUpdate) Marshal(io protocol.IO) {
	pk.Position.Marshal(io)
	pk.Settings.Marshal(io)
	io.Bool(&pk.ShouldTrigger)
	io.Bool(&pk.Waterlogged)
}
