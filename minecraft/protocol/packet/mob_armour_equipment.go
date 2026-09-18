package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// MobArmourEquipment is sent by the server to the client to update the armour an entity is wearing. It is
// sent for both players and other entities, such as zombies.
type MobArmourEquipment struct {
	TargetRuntimeID uint64
	Head            protocol.NetworkItemStackDescriptorSerializedData
	Torso           protocol.NetworkItemStackDescriptorSerializedData
	Legs            protocol.NetworkItemStackDescriptorSerializedData
	Feet            protocol.NetworkItemStackDescriptorSerializedData
	// Body is the item worn on the body of the entity. Items not wearable on the body will not be rendered.
	Body protocol.NetworkItemStackDescriptorSerializedData
}

// ID ...
func (*MobArmourEquipment) ID() uint32 {
	return IDMobArmourEquipment
}

func (pk *MobArmourEquipment) Marshal(io protocol.IO) {
	io.ActorRuntimeID(&pk.TargetRuntimeID)
	pk.Head.Marshal(io)
	pk.Torso.Marshal(io)
	pk.Legs.Marshal(io)
	pk.Feet.Marshal(io)
	pk.Body.Marshal(io)
}
