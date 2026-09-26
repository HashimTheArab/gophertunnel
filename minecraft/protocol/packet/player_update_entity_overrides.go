package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// PlayerUpdateEntityOverrides is sent by the server to modify an entity's properties individually.
type PlayerUpdateEntityOverrides struct {
	// EntityUniqueID is the unique ID of the entity. The unique ID is a value that remains consistent across
	// different sessions of the same world, but most servers simply fill the runtime ID of the entity out for
	// this field.
	EntityUniqueID int64
	// PropertyIndex is the index of the property to modify. The index is unique for each property of an entity.
	PropertyIndex uint32
	Update        protocol.PlayerUpdateEntityOverridesData
}

// ID ...
func (*PlayerUpdateEntityOverrides) ID() uint32 {
	return IDPlayerUpdateEntityOverrides
}

func (pk *PlayerUpdateEntityOverrides) Marshal(io protocol.IO) {
	io.ActorUniqueID(&pk.EntityUniqueID)
	io.Varuint32(&pk.PropertyIndex)
	protocol.MarshalPlayerUpdateEntityOverridesData(io, &pk.Update)
}
