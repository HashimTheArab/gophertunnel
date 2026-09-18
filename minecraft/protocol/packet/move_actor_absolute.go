package packet

import (
	"github.com/go-gl/mathgl/mgl32"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// MoveActorAbsolute is sent by the server to move an entity to an absolute position. It is typically used for
// movements where high accuracy isn't needed, such as for long range teleporting.
type MoveActorAbsolute struct {
	// EntityRuntimeID is the runtime ID of the entity. The runtime ID is unique for each world session, and
	// entities are generally identified in packets using this runtime ID.
	EntityRuntimeID uint64
	Header          uint8
	// Position is the position to spawn the entity on. If the entity is on a distance that the player cannot see
	// it, the entity will still show up if the player moves closer.
	Position      mgl32.Vec3
	RotationX     uint8
	RotationY     uint8
	RotationYHead uint8
}

// ID ...
func (*MoveActorAbsolute) ID() uint32 {
	return IDMoveActorAbsolute
}

func (pk *MoveActorAbsolute) Marshal(io protocol.IO) {
	io.ActorRuntimeID(&pk.EntityRuntimeID)
	io.Uint8(&pk.Header)
	io.Vec3(&pk.Position)
	io.Uint8(&pk.RotationX)
	io.Uint8(&pk.RotationY)
	io.Uint8(&pk.RotationYHead)
}
