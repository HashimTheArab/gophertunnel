package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// ClientboundDataDrivenUICloseScreen is sent by the server to close a data-driven UI screen on the client. If
// FormID is not set, all data-driven UI screens are closed.
type ClientboundDataDrivenUICloseScreen struct {
	// FormID is the optional unique instance ID of the form to close. If not set, all forms are closed.
	FormID protocol.Optional[uint32]
}

// ID returns the protocol ID for ClientboundDataDrivenUICloseScreen.
func (*ClientboundDataDrivenUICloseScreen) ID() uint32 { return IDClientboundDataDrivenUICloseScreen }

// Marshal reads or writes ClientboundDataDrivenUICloseScreen using its canonical wire layout.
func (pk *ClientboundDataDrivenUICloseScreen) Marshal(io protocol.IO) {
	protocol.OptionalFunc(io, &pk.FormID, io.Uint32)
}
