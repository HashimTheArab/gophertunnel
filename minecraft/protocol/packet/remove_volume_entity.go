package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// RemoveVolumeEntity indicates a volume entity to be removed from server to client.
type RemoveVolumeEntity struct {
	EntityNetworkID protocol.EntityNetID
	DimensionType   protocol.DimensionType
}

// Marshal reads or writes RemoveVolumeEntity using its canonical wire layout.
func (x *RemoveVolumeEntity) Marshal(io protocol.IO) {
	x.EntityNetworkID.Marshal(io)
	x.DimensionType.Marshal(io)
}

// ID returns the protocol ID for RemoveVolumeEntity.
func (*RemoveVolumeEntity) ID() uint32 { return IDRemoveVolumeEntity }
