package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// BlockEvent is sent by the server to initiate a certain event that has something to do with blocks in
// specific, for example opening a chest.
type BlockEvent struct {
	// BlockPosition is the position of the block that an event occurred at.
	Position protocol.BlockPos
	// EventType is the type of the block event. The event type decides the way the event data that follows is
	// used. It is one of the constants found above.
	EventType int32
	// EventValue holds event type specific data. For chests for example, opening the chest means the data must
	// hold 1, whereas closing it should hold 0.
	EventData int32
}

// ID ...
func (*BlockEvent) ID() uint32 {
	return IDBlockEvent
}

func (pk *BlockEvent) Marshal(io protocol.IO) {
	pk.Position.Marshal(io)
	io.Varint32(&pk.EventType)
	io.Varint32(&pk.EventData)
}
