package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// ClientBoundAttributeLayerSync is sent by the server to synchronise attribute layers with the client.
type ClientBoundAttributeLayerSync struct {
	// Settings is set if PayloadType is AttributeLayerPayloadTypeUpdateSettings.
	Settings protocol.AttributeLayerSyncData
}

// ID ...
func (*ClientBoundAttributeLayerSync) ID() uint32 {
	return IDClientBoundAttributeLayerSync
}

func (pk *ClientBoundAttributeLayerSync) Marshal(io protocol.IO) {
	protocol.MarshalAttributeLayerSyncData(io, &pk.Settings)
}
