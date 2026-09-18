package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// PartyChanged is sent by the client to the server to indicate that the player's party ID has
// changed.
type PartyChanged struct {
	PartyInfo protocol.Optional[protocol.PlayerPartyInfo]
}

// Marshal reads or writes PartyChanged using its canonical wire layout.
func (x *PartyChanged) Marshal(io protocol.IO) {
	protocol.OptionalMarshaler(io, &x.PartyInfo)
}

// ID returns the protocol ID for PartyChanged.
func (*PartyChanged) ID() uint32 { return IDPartyChanged }
