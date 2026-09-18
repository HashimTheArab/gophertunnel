package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// ServerPresenceInfo is sent by the server to provide the client with presence info.
type ServerPresenceInfo struct {
	// PresenceConfiguration is the presence info to set, or nothing to fall back to the default.
	PresenceInfo protocol.Optional[protocol.ServerConfigurationPresenceConfiguration]
}

// ID returns the protocol ID for ServerPresenceInfo.
func (*ServerPresenceInfo) ID() uint32 { return IDServerPresenceInfo }

// Marshal reads or writes ServerPresenceInfo using its canonical wire layout.
func (pk *ServerPresenceInfo) Marshal(io protocol.IO) {
	protocol.OptionalMarshaler(io, &pk.PresenceInfo)
}
