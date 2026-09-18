package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// ShowProfile is sent by the server to show the XBOX Live profile of one player to another.
type ShowProfile struct {
	// PlayerXUID is the XBOX Live User ID of the player whose profile should be shown to the player. If it is not
	// a valid XUID, the client ignores the packet.
	XUID string
}

// ID returns the protocol ID for ShowProfile.
func (*ShowProfile) ID() uint32 { return IDShowProfile }

// Marshal reads or writes ShowProfile using its canonical wire layout.
func (pk *ShowProfile) Marshal(io protocol.IO) {
	io.String(&pk.XUID)
}
