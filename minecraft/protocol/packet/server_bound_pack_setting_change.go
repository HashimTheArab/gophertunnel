// Code generated from canonical protocol manifest v2. DO NOT EDIT.

package packet

import (
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

type ServerboundPackSettingChange struct {
	PackID           uuid.UUID
	PackSettingName  string
	PackSettingValue protocol.ServerboundPackSettingChangePackSettingValue
}

// Marshal reads or writes ServerboundPackSettingChange using its canonical wire layout.
func (x *ServerboundPackSettingChange) Marshal(io protocol.IO) {
	io.UUID(&x.PackID)
	io.StringLimits(&x.PackSettingName, 0, 128)
	protocol.MarshalServerboundPackSettingChangePackSettingValue(io, &x.PackSettingValue)
}

// ID returns the protocol ID for ServerboundPackSettingChange.
func (*ServerboundPackSettingChange) ID() uint32 { return IDServerboundPackSettingChange }
