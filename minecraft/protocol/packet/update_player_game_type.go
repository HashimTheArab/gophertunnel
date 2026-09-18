package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// UpdatePlayerGameType is sent by the server to change the game mode of a player. It is functionally
// identical to the SetPlayerGameType packet.
type UpdatePlayerGameType struct {
	// GameType is the new game type of the player. It is one of the constants that can be found in
	// set_player_game_type.go. Some of these game types require additional flags to be set in an UpdateAbilities
	// packet for the game mode to obtain its full functionality.
	GameType     protocol.GameType
	TargetPlayer int64
	// Tick is the server tick at which the packet was sent. It is used in relation to
	// CorrectPlayerMovePrediction.
	Tick uint64
}

// ID ...
func (*UpdatePlayerGameType) ID() uint32 {
	return IDUpdatePlayerGameType
}

func (pk *UpdatePlayerGameType) Marshal(io protocol.IO) {
	pk.GameType.Marshal(io)
	io.ActorUniqueID(&pk.TargetPlayer)
	io.PlayerInputTick(&pk.Tick)
}
