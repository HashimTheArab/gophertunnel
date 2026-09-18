package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

const (
	NPCRequestActionSetActions             protocol.RequestType = 0
	NPCRequestActionExecuteAction          protocol.RequestType = 1
	NPCRequestActionExecuteClosingCommands protocol.RequestType = 2
	NPCRequestActionSetName                protocol.RequestType = 3
	NPCRequestActionSetSkin                protocol.RequestType = 4
	NPCRequestActionSetInteractText        protocol.RequestType = 5
	NPCRequestActionExecuteOpeningCommands protocol.RequestType = 6
)

type NpcRequest struct {
	NPCRuntimeID uint64
	RequestType  protocol.RequestType
	Actions      string
	ActionIndex  uint8
	SceneName    string
}

// Marshal reads or writes NpcRequest using its canonical wire layout.
func (x *NpcRequest) Marshal(io protocol.IO) {
	io.ActorRuntimeID(&x.NPCRuntimeID)
	x.RequestType.Marshal(io)
	io.String(&x.Actions)
	io.Uint8(&x.ActionIndex)
	io.String(&x.SceneName)
}

// ID returns the protocol ID for NpcRequest.
func (*NpcRequest) ID() uint32 { return IDNpcRequest }
