package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// RecordStarted is sent by the server to notify the client that a record started playing at a specific block
// position, such as when a music disc is inserted into a jukebox.
type RecordStarted struct {
	// Position is the position of the block that the record started playing at.
	Position          protocol.BlockPos
	ServerSoundHandle protocol.ServerSoundHandle
}

// ID ...
func (*RecordStarted) ID() uint32 {
	return IDRecordStarted
}

func (pk *RecordStarted) Marshal(io protocol.IO) {
	pk.Position.Marshal(io)
	pk.ServerSoundHandle.Marshal(io)
}
