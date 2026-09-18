package protocol

// GameRule contains game rule data.
type GameRule struct {
	// RuleName is the name of the game rule.
	Name string
	// RuleCanBeModified specifies if the game rule can be modified by the player through the in-game
	// UI.
	CanBeModifiedByPlayer bool
	// RuleValue is the new value of the game rule. This is either a bool, uint32 or float32, or nil for
	// the null variant, which carries no value at all.
	Value GameRuleValue
}

// Marshal reads or writes GameRule using its canonical wire layout.
func (x *GameRule) Marshal(io IO) {
	io.String(&x.Name)
	io.Bool(&x.CanBeModifiedByPlayer)
	MarshalGameRuleValue(io, &x.Value)
}
