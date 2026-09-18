// Code generated from canonical protocol manifest v2. DO NOT EDIT.

package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// CameraAimAssistActorPriority is sent by the server to define actor-specific aim assist
// priorities.
type CameraAimAssistActorPriority struct {
	// CameraAimAssistActorPriorityList is a list of aim assist actor priority entries.
	PriorityData []protocol.CameraAimAssistActorPriorityData
}

// Marshal reads or writes CameraAimAssistActorPriority using its canonical wire layout.
func (x *CameraAimAssistActorPriority) Marshal(io protocol.IO) {
	protocol.Slice(io, &x.PriorityData)
}

// ID returns the protocol ID for CameraAimAssistActorPriority.
func (*CameraAimAssistActorPriority) ID() uint32 { return IDCameraAimAssistActorPriority }
