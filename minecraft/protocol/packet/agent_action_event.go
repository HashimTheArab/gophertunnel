package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

type AgentActionEvent struct {
	Identifier string
	Action     protocol.AgentActionType
	Response   string
}

// Marshal reads or writes AgentActionEvent using its canonical wire layout.
func (x *AgentActionEvent) Marshal(io protocol.IO) {
	io.String(&x.Identifier)
	x.Action.Marshal(io)
	io.String(&x.Response)
}

// ID returns the protocol ID for AgentActionEvent.
func (*AgentActionEvent) ID() uint32 { return IDAgentActionEvent }
