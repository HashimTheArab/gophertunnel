package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// StructureTemplateDataRequest is sent by the client to request data of a structure.
type StructureTemplateDataRequest struct {
	// StructureName is the name of the structure that was set in the structure block's UI. This is the name used
	// to export the structure to a file.
	StructureName string
	// StructurePosition is the position of the structure block that has its template data requested.
	Position protocol.BlockPos
	// StructureSettings is a struct of settings that should be used for exporting the structure. These settings
	// are identical to the last sent in the StructureBlockUpdate packet by the client.
	Settings protocol.StructureSettings
	// RequestedOperation specifies the type of template data request that the player sent. It is one of the
	// constants found above.
	RequestType protocol.StructureTemplateRequestOperation
}

// ID ...
func (*StructureTemplateDataRequest) ID() uint32 {
	return IDStructureTemplateDataRequest
}

func (pk *StructureTemplateDataRequest) Marshal(io protocol.IO) {
	io.StringLimits(&pk.StructureName, 0, 256)
	pk.Position.Marshal(io)
	pk.Settings.Marshal(io)
	pk.RequestType.Marshal(io)
}
