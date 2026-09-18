package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

type ClientboundAttributeLayerSync struct {
	Data protocol.AttributeLayerSyncData
}

// Marshal reads or writes ClientboundAttributeLayerSync using its canonical wire layout.
func (x *ClientboundAttributeLayerSync) Marshal(io protocol.IO) {
	protocol.MarshalAttributeLayerSyncData(io, &x.Data)
}

// ID returns the protocol ID for ClientboundAttributeLayerSync.
func (*ClientboundAttributeLayerSync) ID() uint32 { return IDClientboundAttributeLayerSync }
