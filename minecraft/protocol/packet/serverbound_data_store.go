package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// ServerboundDataStore is sent by the client to update a data store property on the server.
type ServerBoundDataStore struct {
	// Update contains the data store update.
	Update protocol.BedrockDDUIDataStoreUpdate
}

// ID ...
func (*ServerBoundDataStore) ID() uint32 {
	return IDServerBoundDataStore
}

func (pk *ServerBoundDataStore) Marshal(io protocol.IO) {
	pk.Update.Marshal(io)
}
