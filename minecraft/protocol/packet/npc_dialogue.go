package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

const (
	NPCDialogueActionOpen  protocol.NpcDialogueActionType = 0
	NPCDialogueActionClose protocol.NpcDialogueActionType = 1
)

type NpcDialogue struct {
	NpcIDRawID            uint64
	NpcDialogueActionType protocol.NpcDialogueActionType
	Dialogue              string
	SceneName             string
	NPCName               string
	ActionJSON            string
}

// Marshal reads or writes NpcDialogue using its canonical wire layout.
func (x *NpcDialogue) Marshal(io protocol.IO) {
	io.Uint64(&x.NpcIDRawID)
	x.NpcDialogueActionType.Marshal(io)
	io.String(&x.Dialogue)
	io.String(&x.SceneName)
	io.String(&x.NPCName)
	io.String(&x.ActionJSON)
}

// ID returns the protocol ID for NpcDialogue.
func (*NpcDialogue) ID() uint32 { return IDNpcDialogue }
