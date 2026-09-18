package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// CameraSpline is sent by the server to define camera spline paths.
type CameraSpline struct {
	// CameraDataSplines is a list of camera spline definitions.
	Splines []protocol.CameraSplineDefinition
}

// ID returns the protocol ID for CameraSpline.
func (*CameraSpline) ID() uint32 { return IDCameraSpline }

// Marshal reads or writes CameraSpline using its canonical wire layout.
func (pk *CameraSpline) Marshal(io protocol.IO) {
	protocol.Slice(io, &pk.Splines)
}
