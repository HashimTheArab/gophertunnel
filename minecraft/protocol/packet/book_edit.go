package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// BookEdit is sent by the client when it edits a book. It is sent each time a modification was made and the
// player stops its typing 'session', rather than simply after closing the book.
type BookEdit struct {
	// InventorySlot is the slot in which the book that was edited may be found. Typically, the server should
	// check if this slot matches the held item slot of the player.
	InventorySlot int32
	Operation     protocol.BookEditAction
}

// ID ...
func (*BookEdit) ID() uint32 {
	return IDBookEdit
}

func (pk *BookEdit) Marshal(io protocol.IO) {
	io.Varint32(&pk.InventorySlot)
	protocol.MarshalBookEditAction(io, &pk.Operation)
}
