package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// CameraInstruction gives a custom camera specific instructions to operate.
type CameraInstruction struct {
	CameraInstruction protocol.CameraInstructionData
}

// Marshal reads or writes CameraInstruction using its canonical wire layout.
func (x *CameraInstruction) Marshal(io protocol.IO) {
	x.CameraInstruction.Marshal(io)
}

// ID returns the protocol ID for CameraInstruction.
func (*CameraInstruction) ID() uint32 { return IDCameraInstruction }
