package packet

import (
	"github.com/go-gl/mathgl/mgl32"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	InteractActionInvalid         protocol.InteractAction = 0
	InteractActionLeaveVehicle    protocol.InteractAction = 3
	InteractActionMouseOverEntity protocol.InteractAction = 4
	InteractActionNPCOpen         protocol.InteractAction = 5
	InteractActionOpenInventory   protocol.InteractAction = 6
)

// Interact is sent by the client when it interacts with another entity in some way. It used to be used for
// normal entity and block interaction, but this is no longer the case now.
type Interact struct {
	Action          protocol.InteractAction
	TargetRuntimeID uint64
	// Position associated with the ActionType above. For the InteractActionMouseOverEntity, this is the position
	// relative to the entity moused over over which the player hovered with its mouse/touch. For the
	// InteractActionLeaveVehicle, this is the position that the player spawns at after leaving the vehicle.
	Position protocol.Optional[mgl32.Vec3]
}

// ID ...
func (*Interact) ID() uint32 {
	return IDInteract
}

func (pk *Interact) Marshal(io protocol.IO) {
	pk.Action.Marshal(io)
	io.ActorRuntimeID(&pk.TargetRuntimeID)
	protocol.OptionalFunc(io, &pk.Position, io.Vec3)
}
