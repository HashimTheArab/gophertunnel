package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

type GuiDataPickItem struct {
	ItemName    string
	ItemEffects string
	HotBarSlot  int32
}

// Marshal reads or writes GuiDataPickItem using its canonical wire layout.
func (x *GuiDataPickItem) Marshal(io protocol.IO) {
	io.String(&x.ItemName)
	io.String(&x.ItemEffects)
	io.Int32(&x.HotBarSlot)
}

// ID returns the protocol ID for GuiDataPickItem.
func (*GuiDataPickItem) ID() uint32 { return IDGuiDataPickItem }
