package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

type ClientboundDataDrivenUICloseScreen struct {
	FormID protocol.Optional[uint32]
}

// Marshal reads or writes ClientboundDataDrivenUICloseScreen using its canonical wire layout.
func (x *ClientboundDataDrivenUICloseScreen) Marshal(io protocol.IO) {
	protocol.OptionalFunc(io, &x.FormID, io.Uint32)
}

// ID returns the protocol ID for ClientboundDataDrivenUICloseScreen.
func (*ClientboundDataDrivenUICloseScreen) ID() uint32 { return IDClientboundDataDrivenUICloseScreen }
