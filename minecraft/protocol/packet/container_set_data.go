package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// ContainerSetData is sent by the server to update specific data of a single container, meaning a block such
// as a furnace or a brewing stand. This data is usually used by the client to display certain features
// client-side.
type ContainerSetData struct {
	// WindowID is the ID of the window that should have its data set. The player must have a window open with the
	// window ID passed, or nothing will happen.
	WindowID uint8
	// Key is the key of the property. It is one of the constants that can be found above. Multiple properties
	// share the same key, but the functionality depends on the type of the container that the data is set to.
	Key int32
	// Value is the value of the property. Its use differs per property.
	Value int32
}

// ID returns the protocol ID for ContainerSetData.
func (*ContainerSetData) ID() uint32 { return IDContainerSetData }

// Marshal reads or writes ContainerSetData using its canonical wire layout.
func (pk *ContainerSetData) Marshal(io protocol.IO) {
	io.Uint8(&pk.WindowID)
	io.Varint32(&pk.Key)
	io.Varint32(&pk.Value)
}
