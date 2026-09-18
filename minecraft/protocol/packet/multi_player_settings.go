package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	EnableMultiPlayer  protocol.MultiplayerSettingsType = 0
	DisableMultiPlayer protocol.MultiplayerSettingsType = 1
	RefreshJoinCode    protocol.MultiplayerSettingsType = 2
)

// MultiplayerSettings is sent by the client to update multi-player related settings server-side and sent back
// to online players by the server. The MultiPlayerSettings packet is a Minecraft: Education Edition packet.
// It has no functionality for the base game.
type MultiplayerSettings struct {
	// ActionType is the action that should be done when this packet is sent. It is one of the constants that may
	// be found above.
	ActionType protocol.MultiplayerSettingsType
}

// ID ...
func (*MultiplayerSettings) ID() uint32 {
	return IDMultiplayerSettings
}

func (pk *MultiplayerSettings) Marshal(io protocol.IO) {
	pk.ActionType.Marshal(io)
}
