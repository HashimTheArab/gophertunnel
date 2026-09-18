package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// ClientboundDataDrivenUIReload is sent by the server to reload the data-driven UI on the client.
type ClientboundDataDrivenUIReload struct {
}

// ID ...
func (*ClientboundDataDrivenUIReload) ID() uint32 {
	return IDClientboundDataDrivenUIReload
}

func (pk *ClientboundDataDrivenUIReload) Marshal(io protocol.IO) {
}
