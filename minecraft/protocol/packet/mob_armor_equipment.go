package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

type MobArmorEquipment struct {
	TargetRuntimeID uint64
	Head            protocol.NetworkItemStackDescriptorSerializedData
	Torso           protocol.NetworkItemStackDescriptorSerializedData
	Legs            protocol.NetworkItemStackDescriptorSerializedData
	Feet            protocol.NetworkItemStackDescriptorSerializedData
	Body            protocol.NetworkItemStackDescriptorSerializedData
}

// Marshal reads or writes MobArmorEquipment using its canonical wire layout.
func (x *MobArmorEquipment) Marshal(io protocol.IO) {
	io.ActorRuntimeID(&x.TargetRuntimeID)
	x.Head.Marshal(io)
	x.Torso.Marshal(io)
	x.Legs.Marshal(io)
	x.Feet.Marshal(io)
	x.Body.Marshal(io)
}

// ID returns the protocol ID for MobArmorEquipment.
func (*MobArmorEquipment) ID() uint32 { return IDMobArmorEquipment }
