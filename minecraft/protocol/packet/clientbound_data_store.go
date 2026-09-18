package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

type ClientboundDataStore struct {
	Updates []protocol.BedrockDDUI
}

// Marshal reads or writes ClientboundDataStore using its canonical wire layout.
func (x *ClientboundDataStore) Marshal(io protocol.IO) {
	protocol.FuncSliceLimits(io, &x.Updates, io.Varuint32, 0, 500, func(value *protocol.BedrockDDUI) {
		protocol.MarshalBedrockDDUI(io, value)
	})
}

// ID returns the protocol ID for ClientboundDataStore.
func (*ClientboundDataStore) ID() uint32 { return IDClientboundDataStore }
