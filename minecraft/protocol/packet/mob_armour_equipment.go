package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// MobArmourEquipment is sent by the server to the client to update the armour an entity is wearing. It is
// sent for both players and other entities, such as zombies.
type MobArmourEquipment struct {
	TargetRuntimeID uint64
	// Helmet is the equipped helmet of the entity. Items that are not wearable on the head will not be rendered
	// by the client. Unlike in Java Edition, blocks cannot be worn.
	Helmet protocol.NetworkItemStackDescriptorSerializedData
	// Chestplate is the chestplate of the entity. Items that are not wearable as chestplate will not be rendered.
	Chestplate protocol.NetworkItemStackDescriptorSerializedData
	// Leggings is the item worn as leggings by the entity. Items not wearable as leggings will not be rendered
	// client-side.
	Leggings protocol.NetworkItemStackDescriptorSerializedData
	// Boots is the item worn as boots by the entity. Items not wearable as boots will not be rendered.
	Boots protocol.NetworkItemStackDescriptorSerializedData
	// Body is the item worn on the body of the entity. Items not wearable on the body will not be rendered.
	Body protocol.NetworkItemStackDescriptorSerializedData
}

// ID ...
func (*MobArmourEquipment) ID() uint32 {
	return IDMobArmourEquipment
}

func (pk *MobArmourEquipment) Marshal(io protocol.IO) {
	io.ActorRuntimeID(&pk.TargetRuntimeID)
	pk.Helmet.Marshal(io)
	pk.Chestplate.Marshal(io)
	pk.Leggings.Marshal(io)
	pk.Boots.Marshal(io)
	pk.Body.Marshal(io)
}
