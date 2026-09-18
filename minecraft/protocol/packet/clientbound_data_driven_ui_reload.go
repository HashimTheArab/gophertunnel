package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

type ClientboundDataDrivenUIReload struct {
}

// Marshal reads or writes ClientboundDataDrivenUIReload using its canonical wire layout.
func (x *ClientboundDataDrivenUIReload) Marshal(io protocol.IO) {
}

// ID returns the protocol ID for ClientboundDataDrivenUIReload.
func (*ClientboundDataDrivenUIReload) ID() uint32 { return IDClientboundDataDrivenUIReload }
