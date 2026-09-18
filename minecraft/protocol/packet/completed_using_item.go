package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// CompletedUsingItem is sent by the server to tell the client that it should be done using the item
// it is currently using.
type CompletedUsingItem struct {
	// ItemID is the item ID of the item that the client completed using. This should typically be the
	// ID of the item held in the hand.
	UsedItemID int16
	// ItemUseMethod is the method of the using of the item that was completed. It is one of the
	// constants that may be found above.
	UseMethod int32
}

// Marshal reads or writes CompletedUsingItem using its canonical wire layout.
func (x *CompletedUsingItem) Marshal(io protocol.IO) {
	io.Int16(&x.UsedItemID)
	io.Int32(&x.UseMethod)
}

// ID returns the protocol ID for CompletedUsingItem.
func (*CompletedUsingItem) ID() uint32 { return IDCompletedUsingItem }
