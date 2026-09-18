package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	MovementEffectTypeGlideBoost   protocol.MovementEffectType = 0
	MovementEffectTypeDolphinBoost protocol.MovementEffectType = 1
	MovementEffectTypeGeyserBoost  protocol.MovementEffectType = 2
)

// MovementEffect is sent by the server to the client to update specific movement effects to allow the client
// to predict its movement. For example, fireworks used during gliding will send this packet to tell the
// client the exact duration of the boost.
type MovementEffect struct {
	TargetRuntimeID uint64
	EffectID        protocol.MovementEffectType
	EffectDuration  int32
	// Tick is the server tick at which the packet was sent. It is used in relation to
	// CorrectPlayerMovePrediction.
	Tick uint64
}

// ID ...
func (*MovementEffect) ID() uint32 {
	return IDMovementEffect
}

func (pk *MovementEffect) Marshal(io protocol.IO) {
	io.ActorRuntimeID(&pk.TargetRuntimeID)
	pk.EffectID.Marshal(io)
	io.Varint32(&pk.EffectDuration)
	io.PlayerInputTick(&pk.Tick)
}
