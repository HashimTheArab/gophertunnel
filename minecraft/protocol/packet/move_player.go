package packet

import (
	"github.com/go-gl/mathgl/mgl32"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	MoveModeNormal   protocol.PlayerPositionModeComponentPositionMode = 0
	MoveModeReset    protocol.PlayerPositionModeComponentPositionMode = 1
	MoveModeTeleport protocol.PlayerPositionModeComponentPositionMode = 2
	MoveModeRotation protocol.PlayerPositionModeComponentPositionMode = 3
)

// MovePlayer is sent by players to send their movement to the server, and by the server to update the
// movement of player entities to other players.
type MovePlayer struct {
	// EntityRuntimeID is the runtime ID of the player. The runtime ID is unique for each world session, and
	// entities are generally identified in packets using this runtime ID.
	EntityRuntimeID uint64
	// Position is the position to spawn the player on. If the player is on a distance that the viewer cannot see
	// it, the player will still show up if the viewer moves closer.
	Position      mgl32.Vec3
	Rotation      mgl32.Vec2
	YHeadRotation float32
	// Mode is the mode of the movement. It specifies the way the player's movement should be shown to other
	// players. It is one of the constants above.
	Mode protocol.PlayerPositionModeComponentPositionMode
	// OnGround specifies if the player is considered on the ground. Note that proxies or hacked clients could
	// fake this to always be true, so it should not be taken for granted.
	OnGround bool
	// RiddenEntityRuntimeID is the runtime ID of the entity that the player might currently be riding. If not
	// riding, this should be left 0.
	RiddenEntityRuntimeID uint64
	TeleportData          protocol.Optional[protocol.MovePlayerTeleportData]
	// Tick is the server tick at which the packet was sent. It is used in relation to
	// CorrectPlayerMovePrediction.
	Tick uint64
}

// ID ...
func (*MovePlayer) ID() uint32 {
	return IDMovePlayer
}

func (pk *MovePlayer) Marshal(io protocol.IO) {
	io.ActorRuntimeID(&pk.EntityRuntimeID)
	io.Vec3(&pk.Position)
	io.Vec2(&pk.Rotation)
	io.Float32(&pk.YHeadRotation)
	pk.Mode.Marshal(io)
	io.Bool(&pk.OnGround)
	io.ActorRuntimeID(&pk.RiddenEntityRuntimeID)
	protocol.OptionalMarshaler(io, &pk.TeleportData)
	io.PlayerInputTick(&pk.Tick)
}
