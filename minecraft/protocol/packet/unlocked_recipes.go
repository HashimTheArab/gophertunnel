package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	UnlockedRecipesTypeEmpty             protocol.PacketType = 0
	UnlockedRecipesTypeInitiallyUnlocked protocol.PacketType = 1
	UnlockedRecipesTypeNewlyUnlocked     protocol.PacketType = 2
	UnlockedRecipesTypeRemoveUnlocked    protocol.PacketType = 3
	UnlockedRecipesTypeRemoveAllUnlocked protocol.PacketType = 4
)

// UnlockedRecipes gives the client a list of recipes that have been unlocked, restricting the recipes that
// appear in the recipe book.
type UnlockedRecipes struct {
	// UnlockType is the type of unlock that the packet represents, and can either be adding or removing a list of
	// recipes. It is one of the constants listed above.
	UnlockType protocol.PacketType
	// Recipes is a list of recipe names that have been unlocked.
	Recipes []string
}

// ID ...
func (*UnlockedRecipes) ID() uint32 {
	return IDUnlockedRecipes
}

func (pk *UnlockedRecipes) Marshal(io protocol.IO) {
	pk.UnlockType.Marshal(io)
	protocol.FuncSlice(io, &pk.Recipes, io.Varuint32, io.String)
}
