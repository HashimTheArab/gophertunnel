package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// ClientboundAttributeLayerSync is sent by the server to synchronise attribute layers with the client.
type ClientboundAttributeLayerSync struct {
	Data protocol.AttributeLayerSyncData
}

// ID returns the protocol ID for ClientboundAttributeLayerSync.
func (*ClientboundAttributeLayerSync) ID() uint32 { return IDClientboundAttributeLayerSync }

// Marshal reads or writes ClientboundAttributeLayerSync using its canonical wire layout.
func (pk *ClientboundAttributeLayerSync) Marshal(io protocol.IO) {
	protocol.MarshalAttributeLayerSyncData(io, &pk.Data)
}
