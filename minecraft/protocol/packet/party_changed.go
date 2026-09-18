package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// PartyChanged is sent by the client to the server to indicate that the player's party ID has changed.
type PartyChanged struct {
	PartyInfo protocol.Optional[protocol.PlayerPartyInfo]
}

// ID ...
func (*PartyChanged) ID() uint32 {
	return IDPartyChanged
}

func (pk *PartyChanged) Marshal(io protocol.IO) {
	protocol.OptionalMarshaler(io, &pk.PartyInfo)
}
