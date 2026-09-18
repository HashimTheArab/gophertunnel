package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	AnimateActionNoAction         protocol.AnimateAction = 0
	AnimateActionSwingArm         protocol.AnimateAction = 1
	AnimateActionStopSleep        protocol.AnimateAction = 3
	AnimateActionCriticalHit      protocol.AnimateAction = 4
	AnimateActionMagicCriticalHit protocol.AnimateAction = 5
)

// Animate is sent by the server to send a player animation from one player to all viewers of that player. It
// is used for a couple of actions, such as arm swimming and critical hits.
type Animate struct {
	// ActionType is the ID of the animation action to execute. It is one of the action type constants that may be
	// found above.
	ActionType protocol.AnimateAction
	// EntityRuntimeID is the runtime ID of the player that the animation should be played upon. The runtime ID is
	// unique for each world session, and entities are generally identified in packets using this runtime ID.
	EntityRuntimeID uint64
	// Data ...
	Data float32
	// SwingSource is the source for swing actions. It is one of the action type constants that may be found
	// above.
	SwingSource protocol.Optional[string]
}

// ID ...
func (*Animate) ID() uint32 {
	return IDAnimate
}

func (pk *Animate) Marshal(io protocol.IO) {
	pk.ActionType.Marshal(io)
	io.ActorRuntimeID(&pk.EntityRuntimeID)
	io.Float32(&pk.Data)
	protocol.OptionalFunc(io, &pk.SwingSource, io.String)
}
