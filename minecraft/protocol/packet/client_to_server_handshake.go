package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// ClientToServerHandshake is sent by the client in response to a ServerToClientHandshake packet
// sent by the server. It is the first encrypted packet in the login handshake and serves as a
// confirmation that encryption is correctly initialised client side.
type ClientToServerHandshake struct {
}

// Marshal reads or writes ClientToServerHandshake using its canonical wire layout.
func (x *ClientToServerHandshake) Marshal(io protocol.IO) {
}

// ID returns the protocol ID for ClientToServerHandshake.
func (*ClientToServerHandshake) ID() uint32 { return IDClientToServerHandshake }
