package packet

import (
	"github.com/go-gl/mathgl/mgl32"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// ServerPlayerPostMovePosition is sent by the server to the client with the player's server position at the end of
// movement. It is currently only used for debug rendering.
type ServerPlayerPostMovePosition struct {
	// Position is the player's position on the server.
	Position mgl32.Vec3
}

// ID ...
func (*ServerPlayerPostMovePosition) ID() uint32 {
	return IDServerPlayerPostMovePosition
}

func (pk *ServerPlayerPostMovePosition) Marshal(io protocol.IO) {
	io.Vec3(&pk.Position)
}
