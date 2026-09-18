package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

const (
	PlayerArmourDamageFlagHelmet     protocol.LegacyArmorSlot = 0
	PlayerArmourDamageFlagChestplate protocol.LegacyArmorSlot = 1
	PlayerArmourDamageFlagLeggings   protocol.LegacyArmorSlot = 2
	PlayerArmourDamageFlagBoots      protocol.LegacyArmorSlot = 3
	PlayerArmourDamageFlagBody       protocol.LegacyArmorSlot = 4
)

type PlayerArmorDamage struct {
	List []protocol.ArmorSlotAndDamagePair
}

// Marshal reads or writes PlayerArmorDamage using its canonical wire layout.
func (x *PlayerArmorDamage) Marshal(io protocol.IO) {
	protocol.SliceLimits(io, &x.List, 0, 5)
}

// ID returns the protocol ID for PlayerArmorDamage.
func (*PlayerArmorDamage) ID() uint32 { return IDPlayerArmorDamage }
