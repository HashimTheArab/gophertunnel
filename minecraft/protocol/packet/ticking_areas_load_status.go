package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// TickingAreasLoadStatus is sent by the server to the client to notify the client of a ticking area's loading
// status.
type TickingAreasLoadStatus struct {
	// WaitingForPreload is true if the server is waiting for the area's preload.
	Preload bool
}

// ID returns the protocol ID for TickingAreasLoadStatus.
func (*TickingAreasLoadStatus) ID() uint32 { return IDTickingAreasLoadStatus }

// Marshal reads or writes TickingAreasLoadStatus using its canonical wire layout.
func (pk *TickingAreasLoadStatus) Marshal(io protocol.IO) {
	io.Bool(&pk.Preload)
}
