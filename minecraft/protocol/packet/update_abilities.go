// Code generated from canonical protocol manifest v2. DO NOT EDIT.

package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// UpdateAbilities is a packet sent from the server to the client to update the abilities of the
// player. It, along with the UpdateAdventureSettings packet, are replacements of the
// AdventureSettings packet since v1.19.10.
type UpdateAbilities struct {
	// Data represents various data about the abilities of a player, such as ability layers or
	// permissions.
	AbilityData protocol.SerializedAbilitiesData
}

// Marshal reads or writes UpdateAbilities using its canonical wire layout.
func (x *UpdateAbilities) Marshal(io protocol.IO) {
	x.AbilityData.Marshal(io)
}

// ID returns the protocol ID for UpdateAbilities.
func (*UpdateAbilities) ID() uint32 { return IDUpdateAbilities }
