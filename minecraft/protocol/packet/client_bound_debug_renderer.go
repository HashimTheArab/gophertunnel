package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// ClientBoundDebugRenderer is sent by the server to spawn an outlined cube on client-side.
type ClientBoundDebugRenderer struct {
	// Type is the type of action. It is one of the constants above.
	Type            string
	DebugMarkerData protocol.Optional[protocol.DebugMarkerData]
}

// ID ...
func (*ClientBoundDebugRenderer) ID() uint32 {
	return IDClientBoundDebugRenderer
}

func (pk *ClientBoundDebugRenderer) Marshal(io protocol.IO) {
	io.String(&pk.Type)
	protocol.OptionalMarshaler(io, &pk.DebugMarkerData)
}
