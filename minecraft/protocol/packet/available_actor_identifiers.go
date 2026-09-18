package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// AvailableActorIdentifiers is sent by the server at the start of the game to let the client know all
// entities that are available on the server.
type AvailableActorIdentifiers struct {
	IdentifierList []byte
}

// Marshal reads or writes AvailableActorIdentifiers using its canonical wire layout.
func (x *AvailableActorIdentifiers) Marshal(io protocol.IO) {
	io.NBT(&x.IdentifierList, protocol.NBTNetwork)
}

// ID returns the protocol ID for AvailableActorIdentifiers.
func (*AvailableActorIdentifiers) ID() uint32 { return IDAvailableActorIdentifiers }
