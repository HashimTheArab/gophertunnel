package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// BookEdit is sent by the client when it edits a book. It is sent each time a modification was made
// and the player stops its typing 'session', rather than simply after closing the book.
type BookEdit struct {
	BookSlot  int32
	Operation protocol.BookEditAction
}

// Marshal reads or writes BookEdit using its canonical wire layout.
func (x *BookEdit) Marshal(io protocol.IO) {
	io.Varint32(&x.BookSlot)
	protocol.MarshalBookEditAction(io, &x.Operation)
}

// ID returns the protocol ID for BookEdit.
func (*BookEdit) ID() uint32 { return IDBookEdit }
