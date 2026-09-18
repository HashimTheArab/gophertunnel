package packet

import (
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// ServerboundPackSettingChange is sent by the client to the server when it changes a setting for a specific
// pack in the pack settings UI.
type ServerBoundPackSettingChange struct {
	// PackID is the UUID of the pack.
	PackID           uuid.UUID
	PackSettingName  string
	PackSettingValue protocol.ServerBoundPackSettingChangePackSettingValue
}

// ID ...
func (*ServerBoundPackSettingChange) ID() uint32 {
	return IDServerBoundPackSettingChange
}

func (pk *ServerBoundPackSettingChange) Marshal(io protocol.IO) {
	io.UUID(&pk.PackID)
	io.StringLimits(&pk.PackSettingName, 0, 128)
	protocol.MarshalServerBoundPackSettingChangePackSettingValue(io, &pk.PackSettingValue)
}
