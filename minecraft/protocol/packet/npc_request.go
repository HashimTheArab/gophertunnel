package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	NPCRequestActionSetActions             protocol.RequestType = 0
	NPCRequestActionExecuteAction          protocol.RequestType = 1
	NPCRequestActionExecuteClosingCommands protocol.RequestType = 2
	NPCRequestActionSetName                protocol.RequestType = 3
	NPCRequestActionSetSkin                protocol.RequestType = 4
	NPCRequestActionSetInteractText        protocol.RequestType = 5
	NPCRequestActionExecuteOpeningCommands protocol.RequestType = 6
)

// NPCRequest is sent by the client when it interacts with an NPC. The packet is specifically made for
// Education Edition, where NPCs are available to use.
type NPCRequest struct {
	NPCRuntimeID uint64
	// RequestType is the type of the request, which depends on the permission that the player has. It will be
	// either a type that indicates that the NPC should show its dialog, or that it should open the editing
	// window.
	RequestType protocol.RequestType
	// CommandString is the command string set in the NPC. It may consist of multiple commands, depending on what
	// the player set in it.
	CommandString string
	// ActionType is the type of the action to execute.
	ActionType uint8
	// SceneName is the name of the scene. This can be left empty to specify the last scene that the player was
	// sent.
	SceneName string
}

// ID ...
func (*NPCRequest) ID() uint32 {
	return IDNPCRequest
}

func (pk *NPCRequest) Marshal(io protocol.IO) {
	io.ActorRuntimeID(&pk.NPCRuntimeID)
	pk.RequestType.Marshal(io)
	io.String(&pk.CommandString)
	io.Uint8(&pk.ActionType)
	io.String(&pk.SceneName)
}
