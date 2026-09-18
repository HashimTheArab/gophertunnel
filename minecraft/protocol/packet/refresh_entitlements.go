package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// RefreshEntitlements is sent by the client to the server to refresh the entitlements of the player.
type RefreshEntitlements struct {
}

// ID returns the protocol ID for RefreshEntitlements.
func (*RefreshEntitlements) ID() uint32 { return IDRefreshEntitlements }

// Marshal reads or writes RefreshEntitlements using its canonical wire layout.
func (pk *RefreshEntitlements) Marshal(io protocol.IO) {
}
