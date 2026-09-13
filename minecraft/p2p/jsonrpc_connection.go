package p2p

import (
	"errors"

	"github.com/google/uuid"
)

// JSONRPCSignaling provides the identifiers required to advertise a JSON-RPC
// signaling connection. Implementations include messaging.Conn.
type JSONRPCSignaling interface {
	NetworkID() string
	PlayerMessagingID() uuid.UUID
}

// NewJSONRPCConnection returns a validated Connection that advertises the
// identifiers exposed by signaling.
func NewJSONRPCConnection(signaling JSONRPCSignaling) (Connection, error) {
	if signaling == nil {
		return Connection{}, errors.New("minecraft/p2p: JSON-RPC signaling is nil")
	}
	c := Connection{
		Type:              ConnectionTypeSignalingOverJSONRPC,
		NetherNetID:       NetherNetID(signaling.NetworkID()),
		PlayerMessagingID: signaling.PlayerMessagingID(),
	}
	return c, c.Validate()
}
