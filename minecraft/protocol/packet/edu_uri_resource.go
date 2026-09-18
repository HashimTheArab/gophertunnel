package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

type EduURIResource struct {
	EduSharedURIResource protocol.EduSharedURIResource
}

// ID ...
func (*EduURIResource) ID() uint32 {
	return IDEduURIResource
}

func (pk *EduURIResource) Marshal(io protocol.IO) {
	pk.EduSharedURIResource.Marshal(io)
}
