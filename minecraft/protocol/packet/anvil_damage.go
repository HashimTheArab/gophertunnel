package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// AnvilDamage is sent by the client to request the dealing damage to an anvil. This packet is completely
// pointless and the server should never listen to it.
type AnvilDamage struct {
	// BlockPosition is the position in the world that the anvil can be found at.
	AnvilPosition protocol.BlockPos
}

// ID returns the protocol ID for AnvilDamage.
func (*AnvilDamage) ID() uint32 { return IDAnvilDamage }

// Marshal reads or writes AnvilDamage using its canonical wire layout.
func (pk *AnvilDamage) Marshal(io protocol.IO) {
	pk.AnvilPosition.Marshal(io)
}
