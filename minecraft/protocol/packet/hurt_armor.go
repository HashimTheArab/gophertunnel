// Code generated from canonical protocol manifest v2. DO NOT EDIT.

package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

type HurtArmor struct {
	Cause       int32
	Damage      int32
	ArmourSlots uint64
}

// Marshal reads or writes HurtArmor using its canonical wire layout.
func (x *HurtArmor) Marshal(io protocol.IO) {
	io.Varint32(&x.Cause)
	io.Varint32(&x.Damage)
	io.Varuint64(&x.ArmourSlots)
}

// ID returns the protocol ID for HurtArmor.
func (*HurtArmor) ID() uint32 { return IDHurtArmor }
