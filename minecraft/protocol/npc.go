// Code generated from canonical protocol manifest v2. DO NOT EDIT.

package protocol

type NpcDialogueActionType int32

// Marshal reads or writes NpcDialogueActionType through its int32 wire encoding.
func (x *NpcDialogueActionType) Marshal(io IO) { io.Varint32((*int32)(x)) }
