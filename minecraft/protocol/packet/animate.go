package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

const (
	AnimateActionNoAction         protocol.AnimateAction = 0
	AnimateActionSwingArm         protocol.AnimateAction = 1
	AnimateActionStopSleep        protocol.AnimateAction = 3
	AnimateActionCriticalHit      protocol.AnimateAction = 4
	AnimateActionMagicCriticalHit protocol.AnimateAction = 5
)

// Animate is sent by the server to send a player animation from one player to all viewers of that
// player. It is used for a couple of actions, such as arm swimming and critical hits.
type Animate struct {
	Action               protocol.AnimateAction
	TargetActorRuntimeID uint64
	// Data ...
	Data float32
	// SwingSource is the source for swing actions. It is one of the action type constants that may be
	// found above.
	SwingSource protocol.Optional[string]
}

// Marshal reads or writes Animate using its canonical wire layout.
func (x *Animate) Marshal(io protocol.IO) {
	x.Action.Marshal(io)
	io.ActorRuntimeID(&x.TargetActorRuntimeID)
	io.Float32(&x.Data)
	protocol.OptionalFunc(io, &x.SwingSource, io.String)
}

// ID returns the protocol ID for Animate.
func (*Animate) ID() uint32 { return IDAnimate }
