// Code generated from canonical protocol manifest v2. DO NOT EDIT.

package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

type PlayerArmorDamage struct {
	List []protocol.ArmorSlotAndDamagePair
}

// Marshal reads or writes PlayerArmorDamage using its canonical wire layout.
func (x *PlayerArmorDamage) Marshal(io protocol.IO) {
	protocol.SliceLimits(io, &x.List, 0, 5)
}

// ID returns the protocol ID for PlayerArmorDamage.
func (*PlayerArmorDamage) ID() uint32 { return IDPlayerArmorDamage }
