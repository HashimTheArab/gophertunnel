package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// DebugInfo is a packet sent by the server to the client. It does not seem to do anything when sent to the
// normal client in 1.16.
type DebugInfo struct {
	EntityID int64
	// Data is the debug data.
	Data []byte
}

// ID ...
func (*DebugInfo) ID() uint32 {
	return IDDebugInfo
}

func (pk *DebugInfo) Marshal(io protocol.IO) {
	io.ActorUniqueID(&pk.EntityID)
	io.Bytes(&pk.Data)
}
