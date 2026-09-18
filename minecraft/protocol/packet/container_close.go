package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// ContainerClose is sent by the server to close a container the player currently has opened, which was opened
// using the ContainerOpen packet, or by the client to tell the server it closed a particular container, such
// as the crafting grid.
type ContainerClose struct {
	WindowID uint8
	// ContainerType is the type of container that the server is trying to close. This is used to validate on the
	// client side whether or not the server's close request is valid.
	ContainerType uint8
	ServerSide    bool
}

// Marshal reads or writes ContainerClose using its canonical wire layout.
func (x *ContainerClose) Marshal(io protocol.IO) {
	io.Uint8(&x.WindowID)
	io.Uint8(&x.ContainerType)
	io.Bool(&x.ServerSide)
}

// ID returns the protocol ID for ContainerClose.
func (*ContainerClose) ID() uint32 { return IDContainerClose }
