package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// GameRulesChanged is sent by the server to the client to update client-side game rules, such as game rules
// like the 'showCoordinates' game rule.
type GameRulesChanged struct {
	RuleData protocol.GameRulesChangedData
}

// ID returns the protocol ID for GameRulesChanged.
func (*GameRulesChanged) ID() uint32 { return IDGameRulesChanged }

// Marshal reads or writes GameRulesChanged using its canonical wire layout.
func (pk *GameRulesChanged) Marshal(io protocol.IO) {
	pk.RuleData.Marshal(io)
}
