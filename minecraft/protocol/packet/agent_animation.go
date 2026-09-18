package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// AgentAnimation is an Education Edition packet sent from the server to the client to make an agent perform
// an animation.
type AgentAnimation struct {
	AgentAnimation protocol.AgentAnimationType
	RuntimeID      uint64
}

// ID ...
func (*AgentAnimation) ID() uint32 {
	return IDAgentAnimation
}

func (pk *AgentAnimation) Marshal(io protocol.IO) {
	pk.AgentAnimation.Marshal(io)
	io.ActorRuntimeID(&pk.RuntimeID)
}
