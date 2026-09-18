package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	AgentActionTypeAttack            protocol.AgentActionType = 1
	AgentActionTypeCollect           protocol.AgentActionType = 2
	AgentActionTypeDestroy           protocol.AgentActionType = 3
	AgentActionTypeDetectRedstone    protocol.AgentActionType = 4
	AgentActionTypeDetectObstacle    protocol.AgentActionType = 5
	AgentActionTypeDrop              protocol.AgentActionType = 6
	AgentActionTypeDropAll           protocol.AgentActionType = 7
	AgentActionTypeInspect           protocol.AgentActionType = 8
	AgentActionTypeInspectData       protocol.AgentActionType = 9
	AgentActionTypeInspectItemCount  protocol.AgentActionType = 10
	AgentActionTypeInspectItemDetail protocol.AgentActionType = 11
	AgentActionTypeInspectItemSpace  protocol.AgentActionType = 12
	AgentActionTypeInteract          protocol.AgentActionType = 13
	AgentActionTypeMove              protocol.AgentActionType = 14
	AgentActionTypePlaceBlock        protocol.AgentActionType = 15
	AgentActionTypeTill              protocol.AgentActionType = 16
	AgentActionTypeTransferItemTo    protocol.AgentActionType = 17
	AgentActionTypeTurn              protocol.AgentActionType = 18
)

// AgentActionEvent is an Education Edition packet sent from the server to the client to return a response to
// a previously requested action.
type AgentActionEvent struct {
	// Identifier is a JSON identifier referenced in the initial action.
	Identifier string
	// Action represents the action type that was requested. It is one of the constants defined above.
	Action protocol.AgentActionType
	// Response is a JSON string containing the response to the action.
	Response string
}

// ID returns the protocol ID for AgentActionEvent.
func (*AgentActionEvent) ID() uint32 { return IDAgentActionEvent }

// Marshal reads or writes AgentActionEvent using its canonical wire layout.
func (pk *AgentActionEvent) Marshal(io protocol.IO) {
	io.String(&pk.Identifier)
	pk.Action.Marshal(io)
	io.String(&pk.Response)
}
