// Code generated from canonical protocol manifest v2. DO NOT EDIT.

package packet

import (
	"github.com/go-gl/mathgl/mgl32"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// CameraAimAssist is sent by the server to the client to set up aim assist for the client's camera.
type CameraAimAssist struct {
	// PresetID is the ID of the preset that has previously been defined in the CameraAimAssistPresets
	// packet.
	Preset string
	// ViewAngle is the maximum angle around the playes's cursor that the aim assist should check for a
	// target, if TargetMode is set to protocol.AimAssistTargetModeAngle.
	Angle mgl32.Vec2
	// Distance is the maximum distance from the player's cursor should check for a target, if
	// TargetMode is set to protocol.AimAssistTargetModeDistance.
	Distance float32
	// TargetMode is the mode that the camera should use for detecting targets. This is currently one of
	// protocol.AimAssistTargetModeAngle or protocol.AimAssistTargetModeDistance.
	TargetMode protocol.TargetMode
	// Action is the action that should be performed with the aim assist. This is one of the constants
	// above.
	Action protocol.CameraAimAssistAction
	// ShowDebugRender specifies if debug render should be shown.
	ShowDebugRender bool
}

// Marshal reads or writes CameraAimAssist using its canonical wire layout.
func (x *CameraAimAssist) Marshal(io protocol.IO) {
	io.String(&x.Preset)
	io.Vec2(&x.Angle)
	io.Float32(&x.Distance)
	protocol.Minimum(io, &x.Distance, 1)
	protocol.Maximum(io, &x.Distance, 16)
	x.TargetMode.Marshal(io)
	x.Action.Marshal(io)
	io.Bool(&x.ShowDebugRender)
}

// ID returns the protocol ID for CameraAimAssist.
func (*CameraAimAssist) ID() uint32 { return IDCameraAimAssist }

const (
	CameraAimAssistActionSet   protocol.CameraAimAssistAction = 0
	CameraAimAssistActionClear protocol.CameraAimAssistAction = 1
)
