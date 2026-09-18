package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	TextureShiftActionInvalid    protocol.ClientboundTextureShiftAction = 0
	TextureShiftActionInitialize protocol.ClientboundTextureShiftAction = 1
	TextureShiftActionStart      protocol.ClientboundTextureShiftAction = 2
	TextureShiftActionSetEnabled protocol.ClientboundTextureShiftAction = 3
	TextureShiftActionSync       protocol.ClientboundTextureShiftAction = 4
)

// ClientboundTextureShift is sent by the server to control texture shift animations on the client.
type ClientboundTextureShift struct {
	// ActionID is the texture shift action to perform. It is one of the constants above.
	ActionID protocol.ClientboundTextureShiftAction
	// CollectionName is the name of the texture shift collection.
	CollectionName string
	// FromStep is the step to shift from.
	FromStep string
	// ToStep is the step to shift to.
	ToStep string
	// AllSteps is a list of all steps in the texture shift.
	AllSteps []string
	// CurrentLengthTicks is the current length of the shift in ticks.
	CurrentLengthTicks uint64
	// TotalLengthTicks is the total length of the shift in ticks.
	TotalLengthTicks uint64
	// Enabled specifies if the texture shift is enabled.
	Enabled bool
}

// ID returns the protocol ID for ClientboundTextureShift.
func (*ClientboundTextureShift) ID() uint32 { return IDClientboundTextureShift }

// Marshal reads or writes ClientboundTextureShift using its canonical wire layout.
func (pk *ClientboundTextureShift) Marshal(io protocol.IO) {
	pk.ActionID.Marshal(io)
	io.String(&pk.CollectionName)
	io.String(&pk.FromStep)
	io.String(&pk.ToStep)
	protocol.FuncSlice(io, &pk.AllSteps, io.Varuint32, io.String)
	io.Varuint64(&pk.CurrentLengthTicks)
	io.Varuint64(&pk.TotalLengthTicks)
	io.Bool(&pk.Enabled)
}
