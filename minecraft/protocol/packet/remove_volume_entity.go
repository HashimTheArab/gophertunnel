package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// RemoveVolumeEntity indicates a volume entity to be removed from server to client.
type RemoveVolumeEntity struct {
	EntityNetworkID protocol.EntityNetID
	DimensionType   protocol.DimensionType
}

// ID ...
func (*RemoveVolumeEntity) ID() uint32 {
	return IDRemoveVolumeEntity
}

func (pk *RemoveVolumeEntity) Marshal(io protocol.IO) {
	pk.EntityNetworkID.Marshal(io)
	pk.DimensionType.Marshal(io)
}
