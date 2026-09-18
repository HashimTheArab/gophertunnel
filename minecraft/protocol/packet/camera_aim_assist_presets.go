package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	CameraAunAssistPresetOperationSet           protocol.CameraAimAssistPresetOperation = 0
	CameraAunAssistPresetOperationAddToExisting protocol.CameraAimAssistPresetOperation = 1
)

// CameraAimAssistPresets is sent by the server to the client to provide a list of categories and presets that
// can be used when sending a CameraAimAssist packet or a CameraInstruction including aim assist.
type CameraAimAssistPresets struct {
	// CameraAimAssistPresets is a list of categories which can be referenced by one of the Presets.
	Categories []protocol.CameraAimAssistCategoryDefinition
	// CameraAimAssistCategories is a list of presets which define a base for how aim assist should behave
	Presets []protocol.CameraAimAssistPresetDefinition
	// Operation is the operation to perform with the presets. It is one of the constants above.
	Operation protocol.CameraAimAssistPresetOperation
}

// ID returns the protocol ID for CameraAimAssistPresets.
func (*CameraAimAssistPresets) ID() uint32 { return IDCameraAimAssistPresets }

// Marshal reads or writes CameraAimAssistPresets using its canonical wire layout.
func (pk *CameraAimAssistPresets) Marshal(io protocol.IO) {
	protocol.Slice(io, &pk.Categories)
	protocol.Slice(io, &pk.Presets)
	pk.Operation.Marshal(io)
}
