// Code generated from canonical protocol manifest v2. DO NOT EDIT.

package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// LecternUpdate is sent by the client to update the server on which page was opened in a book on a
// lectern, or if the book should be removed from it.
type LecternUpdate struct {
	Page      uint8
	PageCount uint8
	Position  protocol.BlockPos
}

// Marshal reads or writes LecternUpdate using its canonical wire layout.
func (x *LecternUpdate) Marshal(io protocol.IO) {
	io.Uint8(&x.Page)
	io.Uint8(&x.PageCount)
	x.Position.Marshal(io)
}

// ID returns the protocol ID for LecternUpdate.
func (*LecternUpdate) ID() uint32 { return IDLecternUpdate }
