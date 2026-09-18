package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	PlayerArmourDamageFlagHelmet     protocol.LegacyArmorSlot = 0
	PlayerArmourDamageFlagChestplate protocol.LegacyArmorSlot = 1
	PlayerArmourDamageFlagLeggings   protocol.LegacyArmorSlot = 2
	PlayerArmourDamageFlagBoots      protocol.LegacyArmorSlot = 3
	PlayerArmourDamageFlagBody       protocol.LegacyArmorSlot = 4
)

// PlayerArmorDamage is sent by the server to damage the armour of a player. It is a very efficient packet,
// but generally it's much easier to just send a slot update for the damaged armour.
type PlayerArmorDamage struct {
	// List is a list of armour entries indicating which pieces of armour should receive damage.
	List []protocol.ArmorSlotAndDamagePair
}

// ID ...
func (*PlayerArmorDamage) ID() uint32 {
	return IDPlayerArmorDamage
}

func (pk *PlayerArmorDamage) Marshal(io protocol.IO) {
	protocol.SliceLimits(io, &pk.List, 0, 5)
}
