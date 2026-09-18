package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// SyncWorldClocks is sent by the server to initialise and synchronise world clocks with the client.
type SyncWorldClocks struct {
	Data protocol.SyncWorldClocksData
}

// ID returns the protocol ID for SyncWorldClocks.
func (*SyncWorldClocks) ID() uint32 { return IDSyncWorldClocks }

// Marshal reads or writes SyncWorldClocks using its canonical wire layout.
func (pk *SyncWorldClocks) Marshal(io protocol.IO) {
	protocol.MarshalSyncWorldClocksData(io, &pk.Data)
}
