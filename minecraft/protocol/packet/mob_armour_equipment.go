package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// MobArmourEquipment is sent by the server to the client to update the armour an entity is wearing. It is
// sent for both players and other entities, such as zombies.
type MobArmourEquipment struct {
	// EntityRuntimeID is the runtime ID of the entity. The runtime ID is unique for each world session, and
	// entities are generally identified in packets using this runtime ID.
	EntityRuntimeID uint64
	// Helmet is the equipped helmet of the entity. Items that are not wearable on the head will not be
	// rendered by the client. Unlike in Java Edition, blocks cannot be worn.
	Helmet protocol.NetworkItemStackDescriptor
	// Chestplate is the chestplate of the entity. Items that are not wearable as chestplate will not be
	// rendered.
	Chestplate protocol.NetworkItemStackDescriptor
	// Leggings is the item worn as leggings by the entity. Items not wearable as leggings will not be
	// rendered client-side.
	Leggings protocol.NetworkItemStackDescriptor
	// Boots is the item worn as boots by the entity. Items not wearable as boots will not be rendered.
	Boots protocol.NetworkItemStackDescriptor
	// Body is the item worn on the body of the entity. Items not wearable on the body will not be rendered.
	Body protocol.NetworkItemStackDescriptor
}

// ID ...
func (*MobArmourEquipment) ID() uint32 {
	return IDMobArmourEquipment
}

func (pk *MobArmourEquipment) Marshal(io protocol.IO) {
	io.Varuint64(&pk.EntityRuntimeID)
	protocol.Single(io, &pk.Helmet)
	protocol.Single(io, &pk.Chestplate)
	protocol.Single(io, &pk.Leggings)
	protocol.Single(io, &pk.Boots)
	protocol.Single(io, &pk.Body)
}
