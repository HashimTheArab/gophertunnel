// Code generated from canonical protocol manifest v2. DO NOT EDIT.

package packet

import (
	"github.com/go-gl/mathgl/mgl32"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

type ServerPlayerPostMovePosition struct {
	Position mgl32.Vec3
}

// Marshal reads or writes ServerPlayerPostMovePosition using its canonical wire layout.
func (x *ServerPlayerPostMovePosition) Marshal(io protocol.IO) {
	io.Vec3(&x.Position)
}

// ID returns the protocol ID for ServerPlayerPostMovePosition.
func (*ServerPlayerPostMovePosition) ID() uint32 { return IDServerPlayerPostMovePosition }
