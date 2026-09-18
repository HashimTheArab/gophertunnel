package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

const (
	ControlSchemeLockedPlayerRelativeStrafe protocol.ControlScheme = 0
	ControlSchemeCameraRelative             protocol.ControlScheme = 1
	ControlSchemeCameraRelativeStrafe       protocol.ControlScheme = 2
	ControlSchemePlayerRelative             protocol.ControlScheme = 3
	ControlSchemePlayerRelativeStrafe       protocol.ControlScheme = 4
)

type ClientboundControlSchemeSet struct {
	ControlScheme protocol.ControlScheme
}

// Marshal reads or writes ClientboundControlSchemeSet using its canonical wire layout.
func (x *ClientboundControlSchemeSet) Marshal(io protocol.IO) {
	x.ControlScheme.Marshal(io)
}

// ID returns the protocol ID for ClientboundControlSchemeSet.
func (*ClientboundControlSchemeSet) ID() uint32 { return IDClientboundControlSchemeSet }
