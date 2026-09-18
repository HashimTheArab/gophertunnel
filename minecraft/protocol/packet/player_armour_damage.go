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

// PlayerArmourDamage is sent by the server to damage the armour of a player. It is a very efficient packet,
// but generally it's much easier to just send a slot update for the damaged armour.
type PlayerArmourDamage struct {
	// List is a list of armour entries indicating which pieces of armour should receive damage.
	List []protocol.PlayerArmourDamageEntry
}

// ID ...
func (*PlayerArmourDamage) ID() uint32 {
	return IDPlayerArmourDamage
}

func (pk *PlayerArmourDamage) Marshal(io protocol.IO) {
	protocol.SliceLimits(io, &pk.List, 0, 5)
}
