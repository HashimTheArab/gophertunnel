package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// SimpleEvent is used for enabling or disabling commands and for unlocking world template settings
// (both unlocking UI buttons on client and the actual setting on the server). This is fired from
// the client to the server and a SetCommandsEnabled is sent back when enabling commands.
type SimpleEvent struct {
	Type protocol.Subtype
}

// Marshal reads or writes SimpleEvent using its canonical wire layout.
func (x *SimpleEvent) Marshal(io protocol.IO) {
	x.Type.Marshal(io)
}

// ID returns the protocol ID for SimpleEvent.
func (*SimpleEvent) ID() uint32 { return IDSimpleEvent }

const (
	SubtypeUninitializedSubtype            protocol.Subtype = 0
	SimpleEventCommandsEnabled             protocol.Subtype = 1
	SimpleEventCommandsDisabled            protocol.Subtype = 2
	SimpleEventUnlockWorldTemplateSettings protocol.Subtype = 3
)
