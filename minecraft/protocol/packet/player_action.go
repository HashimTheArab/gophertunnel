package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// PlayerAction is sent by the client when it executes any action, for example starting to sprint, swim,
// starting the breaking of a block, dropping an item, etc.
type PlayerAction struct {
	PlayerRuntimeID uint64
	Action          protocol.PlayerActionType
	// BlockPosition is the position of the target block, if the action with the ActionType set concerned a block.
	// If that is not the case, the block position will be zero.
	BlockPosition protocol.BlockPos
	ResultPos     protocol.BlockPos
	Face          int32
}

// ID ...
func (*PlayerAction) ID() uint32 {
	return IDPlayerAction
}

func (pk *PlayerAction) Marshal(io protocol.IO) {
	io.ActorRuntimeID(&pk.PlayerRuntimeID)
	pk.Action.Marshal(io)
	pk.BlockPosition.Marshal(io)
	pk.ResultPos.Marshal(io)
	io.Varint32(&pk.Face)
}
