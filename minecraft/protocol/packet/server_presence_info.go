package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// ServerPresenceInfo is sent by the server to provide the client with presence info.
type ServerPresenceInfo struct {
	// PresenceConfiguration is the presence info to set, or nothing to fall back to the default.
	PresenceInfo protocol.Optional[protocol.ServerConfigurationPresenceConfiguration]
}

// ID ...
func (*ServerPresenceInfo) ID() uint32 {
	return IDServerPresenceInfo
}

func (pk *ServerPresenceInfo) Marshal(io protocol.IO) {
	protocol.OptionalMarshaler(io, &pk.PresenceInfo)
}
