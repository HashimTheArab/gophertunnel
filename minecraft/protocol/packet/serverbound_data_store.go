package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// ServerboundDataStore is sent by the client to update a data store property on the server.
type ServerboundDataStore struct {
	// Update contains the data store update.
	Update protocol.BedrockDDUIDataStoreUpdate
}

// ID ...
func (*ServerboundDataStore) ID() uint32 {
	return IDServerboundDataStore
}

func (pk *ServerboundDataStore) Marshal(io protocol.IO) {
	pk.Update.Marshal(io)
}
