package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// Camera is sent by the server to use an Education Edition camera on a player. It produces an image
// client-side.
type Camera struct {
	CameraID       int64
	TargetPlayerID int64
}

// ID ...
func (*Camera) ID() uint32 {
	return IDCamera
}

func (pk *Camera) Marshal(io protocol.IO) {
	io.ActorUniqueID(&pk.CameraID)
	io.ActorUniqueID(&pk.TargetPlayerID)
}
