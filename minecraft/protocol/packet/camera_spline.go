// Code generated from canonical protocol manifest v2. DO NOT EDIT.

package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// CameraSpline is sent by the server to define camera spline paths.
type CameraSpline struct {
	// CameraDataSplines is a list of camera spline definitions.
	Splines []protocol.CameraSplineDefinition
}

// Marshal reads or writes CameraSpline using its canonical wire layout.
func (x *CameraSpline) Marshal(io protocol.IO) {
	protocol.Slice(io, &x.Splines)
}

// ID returns the protocol ID for CameraSpline.
func (*CameraSpline) ID() uint32 { return IDCameraSpline }
