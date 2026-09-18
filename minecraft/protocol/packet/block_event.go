// Code generated from canonical protocol manifest v2. DO NOT EDIT.

package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// BlockEvent is sent by the server to initiate a certain event that has something to do with blocks
// in specific, for example opening a chest.
type BlockEvent struct {
	// BlockPosition is the position of the block that an event occurred at.
	Position protocol.BlockPos
	// EventType is the type of the block event. The event type decides the way the event data that
	// follows is used. It is one of the constants found above.
	EventType int32
	// EventValue holds event type specific data. For chests for example, opening the chest means the
	// data must hold 1, whereas closing it should hold 0.
	EventData int32
}

// Marshal reads or writes BlockEvent using its canonical wire layout.
func (x *BlockEvent) Marshal(io protocol.IO) {
	x.Position.Marshal(io)
	io.Varint32(&x.EventType)
	io.Varint32(&x.EventData)
}

// ID returns the protocol ID for BlockEvent.
func (*BlockEvent) ID() uint32 { return IDBlockEvent }
