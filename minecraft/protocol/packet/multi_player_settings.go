package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

const (
	EnableMultiPlayer  protocol.MultiplayerSettingsType = 0
	DisableMultiPlayer protocol.MultiplayerSettingsType = 1
	RefreshJoinCode    protocol.MultiplayerSettingsType = 2
)

type MultiplayerSettings struct {
	ActionType protocol.MultiplayerSettingsType
}

// Marshal reads or writes MultiplayerSettings using its canonical wire layout.
func (x *MultiplayerSettings) Marshal(io protocol.IO) {
	x.ActionType.Marshal(io)
}

// ID returns the protocol ID for MultiplayerSettings.
func (*MultiplayerSettings) ID() uint32 { return IDMultiplayerSettings }
