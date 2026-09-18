package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

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

// StructureBlockUpdate is sent by the client when it updates a structure block using the in-game
// UI. The data it contains depends on the type of structure block that it is. In Minecraft Bedrock
// Edition v1.11, there is only the Export structure block type, but in v1.13 the ones present in
// Java Edition will, according to the wiki, be added too.
type StructureBlockUpdate struct {
	BlockPosition protocol.BlockPos
	StructureData protocol.StructureEditorData
	Trigger       bool
	IsWaterlogged bool
}

// Marshal reads or writes StructureBlockUpdate using its canonical wire layout.
func (x *StructureBlockUpdate) Marshal(io protocol.IO) {
	x.BlockPosition.Marshal(io)
	x.StructureData.Marshal(io)
	io.Bool(&x.Trigger)
	io.Bool(&x.IsWaterlogged)
}

// ID returns the protocol ID for StructureBlockUpdate.
func (*StructureBlockUpdate) ID() uint32 { return IDStructureBlockUpdate }
