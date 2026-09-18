package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// Camera is sent by the server to use an Education Edition camera on a player. It produces an image
// client-side.
type Camera struct {
	CameraID       int64
	TargetPlayerID int64
}

// Marshal reads or writes Camera using its canonical wire layout.
func (x *Camera) Marshal(io protocol.IO) {
	io.ActorUniqueID(&x.CameraID)
	io.ActorUniqueID(&x.TargetPlayerID)
}

// ID returns the protocol ID for Camera.
func (*Camera) ID() uint32 { return IDCamera }
