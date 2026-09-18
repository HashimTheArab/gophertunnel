// Code generated from canonical protocol manifest v2. DO NOT EDIT.

package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// UnlockedRecipes gives the client a list of recipes that have been unlocked, restricting the
// recipes that appear in the recipe book.
type UnlockedRecipes struct {
	PacketType          protocol.PacketType
	UnlockedRecipesList []string
}

// Marshal reads or writes UnlockedRecipes using its canonical wire layout.
func (x *UnlockedRecipes) Marshal(io protocol.IO) {
	x.PacketType.Marshal(io)
	protocol.FuncSlice(io, &x.UnlockedRecipesList, io.Varuint32, io.String)
}

// ID returns the protocol ID for UnlockedRecipes.
func (*UnlockedRecipes) ID() uint32 { return IDUnlockedRecipes }

const (
	UnlockedRecipesTypeEmpty             protocol.ItemDescriptorType = 0
	UnlockedRecipesTypeInitiallyUnlocked protocol.ItemDescriptorType = 1
	UnlockedRecipesTypeNewlyUnlocked     protocol.ItemDescriptorType = 2
	UnlockedRecipesTypeRemoveUnlocked    protocol.ItemDescriptorType = 3
)
