package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// CameraShake is sent by the server to make the camera shake client-side. This feature was added
// for map- making partners.
type CameraShake struct {
	// Intensity is the intensity of the shaking. The client limits this value to 4, so anything higher
	// may not work.
	Intensity   float32
	Seconds     float32
	ShakeType   protocol.CameraShakeType
	ShakeAction protocol.CameraShakeAction
}

// Marshal reads or writes CameraShake using its canonical wire layout.
func (x *CameraShake) Marshal(io protocol.IO) {
	io.Float32(&x.Intensity)
	io.Float32(&x.Seconds)
	x.ShakeType.Marshal(io)
	x.ShakeAction.Marshal(io)
}

// ID returns the protocol ID for CameraShake.
func (*CameraShake) ID() uint32 { return IDCameraShake }

const (
	CameraShakeActionAdd  protocol.CameraShakeAction = 0
	CameraShakeActionStop protocol.CameraShakeAction = 1
)

const (
	CameraShakeTypePositional protocol.CameraShakeType = 0
	CameraShakeTypeRotational protocol.CameraShakeType = 1
)
