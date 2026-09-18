package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// AvailableActorIdentifiers is sent by the server at the start of the game to let the client know all
// entities that are available on the server.
type AvailableActorIdentifiers struct {
	IdentifierList []byte
}

// ID returns the protocol ID for AvailableActorIdentifiers.
func (*AvailableActorIdentifiers) ID() uint32 { return IDAvailableActorIdentifiers }

// Marshal reads or writes AvailableActorIdentifiers using its canonical wire layout.
func (pk *AvailableActorIdentifiers) Marshal(io protocol.IO) {
	io.NBT(&pk.IdentifierList, protocol.NBTNetwork)
}
