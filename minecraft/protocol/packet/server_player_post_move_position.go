package packet

import (
	"github.com/go-gl/mathgl/mgl32"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// ServerPlayerPostMovePosition is sent by the server with a debug-draw position after player movement.
type ServerPlayerPostMovePosition struct {
	// Position is the debug-draw position sent by the server.
	Position mgl32.Vec3
}

// ID ...
func (*ServerPlayerPostMovePosition) ID() uint32 {
	return IDServerPlayerPostMovePosition
}

func (pk *ServerPlayerPostMovePosition) Marshal(io protocol.IO) {
	io.Vec3(&pk.Position)
}
