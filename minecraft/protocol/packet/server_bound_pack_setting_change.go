package packet

import (
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// ServerboundPackSettingChange is sent by the client to the server when it changes a setting for a specific
// pack in the pack settings UI.
type ServerboundPackSettingChange struct {
	// PackID is the UUID of the pack.
	PackID           uuid.UUID
	PackSettingName  string
	PackSettingValue protocol.ServerboundPackSettingChangePackSettingValue
}

// ID returns the protocol ID for ServerboundPackSettingChange.
func (*ServerboundPackSettingChange) ID() uint32 { return IDServerboundPackSettingChange }

// Marshal reads or writes ServerboundPackSettingChange using its canonical wire layout.
func (pk *ServerboundPackSettingChange) Marshal(io protocol.IO) {
	io.UUID(&pk.PackID)
	io.StringLimits(&pk.PackSettingName, 0, 128)
	protocol.MarshalServerboundPackSettingChangePackSettingValue(io, &pk.PackSettingValue)
}
