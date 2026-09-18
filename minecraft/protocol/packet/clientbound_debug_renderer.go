package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

type ClientboundDebugRenderer struct {
	Type            string
	DebugMarkerData protocol.Optional[protocol.DebugMarkerData]
}

// Marshal reads or writes ClientboundDebugRenderer using its canonical wire layout.
func (x *ClientboundDebugRenderer) Marshal(io protocol.IO) {
	io.String(&x.Type)
	protocol.OptionalMarshaler(io, &x.DebugMarkerData)
}

// ID returns the protocol ID for ClientboundDebugRenderer.
func (*ClientboundDebugRenderer) ID() uint32 { return IDClientboundDebugRenderer }
