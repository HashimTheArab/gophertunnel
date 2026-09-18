package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// RequestNetworkSettings is sent by the client to request network settings, such as compression, from the
// server.
type RequestNetworkSettings struct {
	// ClientNetworkVersion is the protocol version of the player. The player is disconnected if the protocol is
	// incompatible with the protocol of the server.
	ClientProtocol int32
}

// ID ...
func (*RequestNetworkSettings) ID() uint32 {
	return IDRequestNetworkSettings
}

func (pk *RequestNetworkSettings) Marshal(io protocol.IO) {
	io.BEInt32(&pk.ClientProtocol)
	protocol.Minimum(io, &pk.ClientProtocol, 2168)
	protocol.Maximum(io, &pk.ClientProtocol, 2168)
}
