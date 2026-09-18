package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// LevelEventGeneric is sent by the server to send a 'generic' level event to the client. This packet sends an
// NBT serialised object and may for that reason be used for any event holding additional data.
type LevelEventGeneric struct {
	// EventID is a unique identifier that identifies the event called. The data that follows has fields in the
	// NBT depending on what event it is.
	EventID int32
	CTD     []byte
}

// ID returns the protocol ID for LevelEventGeneric.
func (*LevelEventGeneric) ID() uint32 { return IDLevelEventGeneric }

// Marshal reads or writes LevelEventGeneric using its canonical wire layout.
func (pk *LevelEventGeneric) Marshal(io protocol.IO) {
	io.Varint32(&pk.EventID)
	io.NBT(&pk.CTD, protocol.NBTNetwork)
}
