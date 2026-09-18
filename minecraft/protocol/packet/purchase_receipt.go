package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// PurchaseReceipt is sent by the client to the server to notify the server it purchased an item
// from the Marketplace store that was offered by the server. The packet is only used for partnered
// servers.
type PurchaseReceipt struct {
	// PurchaseReceipts is a list of receipts, or proofs of purchases, for the offers that have been
	// purchased by the player.
	Receipts []string
}

// Marshal reads or writes PurchaseReceipt using its canonical wire layout.
func (x *PurchaseReceipt) Marshal(io protocol.IO) {
	protocol.FuncSliceLimits(io, &x.Receipts, io.Varuint32, 0, 10000, io.String)
}

// ID returns the protocol ID for PurchaseReceipt.
func (*PurchaseReceipt) ID() uint32 { return IDPurchaseReceipt }
