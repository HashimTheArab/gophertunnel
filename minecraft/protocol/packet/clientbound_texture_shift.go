package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

type ClientboundTextureShift struct {
	ActionID           protocol.ClientboundTextureShiftAction
	CollectionName     string
	FromStep           string
	ToStep             string
	AllSteps           []string
	CurrentLengthTicks uint64
	TotalLengthTicks   uint64
	Enabled            bool
}

// Marshal reads or writes ClientboundTextureShift using its canonical wire layout.
func (x *ClientboundTextureShift) Marshal(io protocol.IO) {
	x.ActionID.Marshal(io)
	io.String(&x.CollectionName)
	io.String(&x.FromStep)
	io.String(&x.ToStep)
	protocol.FuncSlice(io, &x.AllSteps, io.Varuint32, io.String)
	io.Varuint64(&x.CurrentLengthTicks)
	io.Varuint64(&x.TotalLengthTicks)
	io.Bool(&x.Enabled)
}

// ID returns the protocol ID for ClientboundTextureShift.
func (*ClientboundTextureShift) ID() uint32 { return IDClientboundTextureShift }

const (
	TextureShiftActionInvalid    protocol.ClientboundTextureShiftAction = 0
	TextureShiftActionInitialize protocol.ClientboundTextureShiftAction = 1
	TextureShiftActionStart      protocol.ClientboundTextureShiftAction = 2
	TextureShiftActionSetEnabled protocol.ClientboundTextureShiftAction = 3
	TextureShiftActionSync       protocol.ClientboundTextureShiftAction = 4
)
