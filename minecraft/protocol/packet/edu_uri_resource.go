package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

type EduURIResource struct {
	EduSharedURIResource protocol.EduSharedURIResource
}

// ID returns the protocol ID for EduURIResource.
func (*EduURIResource) ID() uint32 { return IDEduURIResource }

// Marshal reads or writes EduURIResource using its canonical wire layout.
func (pk *EduURIResource) Marshal(io protocol.IO) {
	pk.EduSharedURIResource.Marshal(io)
}
