package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// SetPlayerGameType is sent by the server to update the game type, which is otherwise known as the
// game mode, of a player.
type SetPlayerGameType struct {
	PlayerGameType protocol.GameType
}

// Marshal reads or writes SetPlayerGameType using its canonical wire layout.
func (x *SetPlayerGameType) Marshal(io protocol.IO) {
	x.PlayerGameType.Marshal(io)
}

// ID returns the protocol ID for SetPlayerGameType.
func (*SetPlayerGameType) ID() uint32 { return IDSetPlayerGameType }

const (
	GameTypeUndefined protocol.GameType = -1
	GameTypeSurvival  protocol.GameType = 0
	GameTypeCreative  protocol.GameType = 1
	GameTypeAdventure protocol.GameType = 2
	GameTypeDefault   protocol.GameType = 5
	GameTypeSpectator protocol.GameType = 6
)
