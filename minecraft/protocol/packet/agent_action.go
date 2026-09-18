package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

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
