package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// UpdateAdventureSettings is a packet sent from the server to the client to update the adventure
// settings of the player. It, along with the UpdateAbilities packet, are replacements of the
// AdventureSettings packet since v1.19.10.
type UpdateAdventureSettings struct {
	AdventureSettings protocol.AdventureSettings
}

// Marshal reads or writes UpdateAdventureSettings using its canonical wire layout.
func (x *UpdateAdventureSettings) Marshal(io protocol.IO) {
	x.AdventureSettings.Marshal(io)
}

// ID returns the protocol ID for UpdateAdventureSettings.
func (*UpdateAdventureSettings) ID() uint32 { return IDUpdateAdventureSettings }
