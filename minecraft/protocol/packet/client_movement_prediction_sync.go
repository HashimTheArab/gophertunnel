package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// ClientMovementPredictionSync is sent by the client to the server periodically if the client has received
// movement corrections from the server, containing information about client-predictions that are relevant to
// movement.
type ClientMovementPredictionSync struct {
	// ActorFlags is a bitset of all the flags that are currently set for the client.
	ActorFlags         protocol.ActorDataFlagComponent
	EntityBoundingBox  protocol.ActorDataBoundingBoxComponent
	MovementAttributes [9]float32
	// EntityUniqueID is the unique ID of the entity that the prediction data applies to.
	EntityUniqueID int64
	// Flying specifies if the client is currently flying.
	Flying bool
}

// ID ...
func (*ClientMovementPredictionSync) ID() uint32 {
	return IDClientMovementPredictionSync
}

func (pk *ClientMovementPredictionSync) Marshal(io protocol.IO) {
	pk.ActorFlags.Marshal(io)
	pk.EntityBoundingBox.Marshal(io)
	for index1 := range pk.MovementAttributes {
		io.Float32(&pk.MovementAttributes[index1])
	}
	io.ActorUniqueID(&pk.EntityUniqueID)
	io.Bool(&pk.Flying)
}
