package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// SetDifficulty is sent by the server to update the client-side difficulty of the client. The actual effect
// of this packet on the client isn't very significant, as the difficulty is handled server-side.
type SetDifficulty struct {
	// Difficulty is the new difficulty that the world has.
	Difficulty uint32
}

// ID returns the protocol ID for SetDifficulty.
func (*SetDifficulty) ID() uint32 { return IDSetDifficulty }

// Marshal reads or writes SetDifficulty using its canonical wire layout.
func (pk *SetDifficulty) Marshal(io protocol.IO) {
	io.Varuint32(&pk.Difficulty)
}
