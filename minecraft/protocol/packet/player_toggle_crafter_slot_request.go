package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// PlayerToggleCrafterSlotRequest is sent by the client when it tries to toggle the state of a slot
// within a Crafter.
type PlayerToggleCrafterSlotRequest struct {
	// PosX is the X position of the Crafter that is being modified.
	PosX int32
	// PosY is the Y position of the Crafter that is being modified.
	PosY int32
	// PosZ is the Z position of the Crafter that is being modified.
	PosZ     int32
	Slot     uint8
	Disabled bool
}

// Marshal reads or writes PlayerToggleCrafterSlotRequest using its canonical wire layout.
func (x *PlayerToggleCrafterSlotRequest) Marshal(io protocol.IO) {
	io.Int32(&x.PosX)
	io.Int32(&x.PosY)
	io.Int32(&x.PosZ)
	io.Uint8(&x.Slot)
	io.Bool(&x.Disabled)
}

// ID returns the protocol ID for PlayerToggleCrafterSlotRequest.
func (*PlayerToggleCrafterSlotRequest) ID() uint32 { return IDPlayerToggleCrafterSlotRequest }
