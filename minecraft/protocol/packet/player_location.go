package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	PlayerLocationTypeCoordinates protocol.PlayerLocationType = 0
)

// PlayerLocation is sent by the server to the client to either update a player's position on the locator bar,
// or remove them completely. The client will determine how to render the player on the locator bar based on
// their own distance to Position.
type PlayerLocation struct {
	TargetEntityID int64
	// Position is the position of the player to be used on the locator bar. This is only set when the Type is
	// PlayerLocationTypeCoordinates.
	Position protocol.PlayerLocationData
}

// ID ...
func (*PlayerLocation) ID() uint32 {
	return IDPlayerLocation
}

func (pk *PlayerLocation) Marshal(io protocol.IO) {
	io.ActorUniqueID(&pk.TargetEntityID)
	protocol.MarshalPlayerLocationData(io, &pk.Position)
}
