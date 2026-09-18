// Code generated from canonical protocol manifest v2. DO NOT EDIT.

package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

type PlayerHotbar struct {
	SelectedHotBarSlot uint32
	WindowID           uint8
	SelectHotBarSlot   bool
}

// Marshal reads or writes PlayerHotbar using its canonical wire layout.
func (x *PlayerHotbar) Marshal(io protocol.IO) {
	io.Varuint32(&x.SelectedHotBarSlot)
	io.Uint8(&x.WindowID)
	io.Bool(&x.SelectHotBarSlot)
}

// ID returns the protocol ID for PlayerHotbar.
func (*PlayerHotbar) ID() uint32 { return IDPlayerHotbar }
