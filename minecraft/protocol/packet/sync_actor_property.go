package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// SyncActorProperty is an alternative to synced actor data.
type SyncActorProperty struct {
	// PropertyData ...
	PropertyData []byte
}

// Marshal reads or writes SyncActorProperty using its canonical wire layout.
func (x *SyncActorProperty) Marshal(io protocol.IO) {
	io.NBT(&x.PropertyData, protocol.NBTNetwork)
}

// ID returns the protocol ID for SyncActorProperty.
func (*SyncActorProperty) ID() uint32 { return IDSyncActorProperty }
