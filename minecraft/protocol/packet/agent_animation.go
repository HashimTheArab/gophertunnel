package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// AgentAnimation is an Education Edition packet sent from the server to the client to make an agent
// perform an animation.
type AgentAnimation struct {
	AgentAnimation protocol.AgentAnimationType
	RuntimeID      uint64
}

// Marshal reads or writes AgentAnimation using its canonical wire layout.
func (x *AgentAnimation) Marshal(io protocol.IO) {
	x.AgentAnimation.Marshal(io)
	io.ActorRuntimeID(&x.RuntimeID)
}

// ID returns the protocol ID for AgentAnimation.
func (*AgentAnimation) ID() uint32 { return IDAgentAnimation }
