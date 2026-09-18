package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	CameraShakeActionAdd  protocol.CameraShakeAction = 0
	CameraShakeActionStop protocol.CameraShakeAction = 1
)

const (
	CameraShakeTypePositional protocol.CameraShakeType = 0
	CameraShakeTypeRotational protocol.CameraShakeType = 1
)

// CameraShake is sent by the server to make the camera shake client-side. This feature was added for map-
// making partners.
type CameraShake struct {
	// Intensity is the intensity of the shaking. The client limits this value to 4, so anything higher may not
	// work.
	Intensity float32
	// Duration is the number of seconds the camera will shake for.
	Duration float32
	// Type is the type of shake, and is one of the constants listed above. The different type affects how the
	// shake looks in game.
	Type protocol.CameraShakeType
	// Action is the action to be performed, and is one of the constants listed above. Currently the different
	// actions will either add or stop shaking the client.
	Action protocol.CameraShakeAction
}

// ID returns the protocol ID for CameraShake.
func (*CameraShake) ID() uint32 { return IDCameraShake }

// Marshal reads or writes CameraShake using its canonical wire layout.
func (pk *CameraShake) Marshal(io protocol.IO) {
	io.Float32(&pk.Intensity)
	io.Float32(&pk.Duration)
	pk.Type.Marshal(io)
	pk.Action.Marshal(io)
}
