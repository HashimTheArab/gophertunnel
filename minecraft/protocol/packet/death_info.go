package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// DeathInfo is a packet sent from the server to the client expected to be sent when a player dies. It
// contains messages related to the player's death, which are shown on the death screen as of v1.19.10.
type DeathInfo struct {
	// DeathCauseAttackName is the cause of the player's death, such as "suffocation" or "suicide".
	Cause string
	// DeathCauseMessageList is a list of death messages to be shown on the death screen.
	Messages []string
}

// ID returns the protocol ID for DeathInfo.
func (*DeathInfo) ID() uint32 { return IDDeathInfo }

// Marshal reads or writes DeathInfo using its canonical wire layout.
func (pk *DeathInfo) Marshal(io protocol.IO) {
	io.String(&pk.Cause)
	protocol.FuncSlice(io, &pk.Messages, io.Varuint32, io.String)
}
