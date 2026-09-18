package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// ClientboundAttributeLayerSync is sent by the server to synchronise attribute layers with the client.
type ClientboundAttributeLayerSync struct {
	Data protocol.AttributeLayerSyncData
}

// ID ...
func (*ClientboundAttributeLayerSync) ID() uint32 {
	return IDClientboundAttributeLayerSync
}

func (pk *ClientboundAttributeLayerSync) Marshal(io protocol.IO) {
	protocol.MarshalAttributeLayerSyncData(io, &pk.Data)
}
