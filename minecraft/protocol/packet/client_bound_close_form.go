package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// ClientboundCloseForm is sent by the server to clear the entire form stack of the client. This means that
// all forms that are currently open will be closed. This does not affect inventories and other containers.
type ClientboundCloseForm struct {
}

// ID ...
func (*ClientboundCloseForm) ID() uint32 {
	return IDClientboundCloseForm
}

func (pk *ClientboundCloseForm) Marshal(io protocol.IO) {
}
