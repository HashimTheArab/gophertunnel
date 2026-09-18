package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// ClientboundAttributeLayerSync is sent by the server to synchronise attribute layers with the client.
type ClientBoundAttributeLayerSync struct {
	Data protocol.AttributeLayerSyncData
}

// ID ...
func (*ClientBoundAttributeLayerSync) ID() uint32 {
	return IDClientBoundAttributeLayerSync
}

func (pk *ClientBoundAttributeLayerSync) Marshal(io protocol.IO) {
	protocol.MarshalAttributeLayerSyncData(io, &pk.Data)
}
