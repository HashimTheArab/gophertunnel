package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	InventoryLayoutNone           protocol.InventoryLayout = 0
	InventoryLayoutInventoryOnly  protocol.InventoryLayout = 1
	InventoryLayoutDefault        protocol.InventoryLayout = 2
	InventoryLayoutRecipeBookOnly protocol.InventoryLayout = 3
)

const (
	InventoryLeftTabNone         protocol.InventoryLeftTabIndex = 0
	InventoryLeftTabConstruction protocol.InventoryLeftTabIndex = 1
	InventoryLeftTabEquipment    protocol.InventoryLeftTabIndex = 2
	InventoryLeftTabItems        protocol.InventoryLeftTabIndex = 3
	InventoryLeftTabNature       protocol.InventoryLeftTabIndex = 4
	InventoryLeftTabSearch       protocol.InventoryLeftTabIndex = 5
	InventoryLeftTabSurvival     protocol.InventoryLeftTabIndex = 6
)

const (
	InventoryRightTabNone       protocol.InventoryRightTabIndex = 0
	InventoryRightTabFullScreen protocol.InventoryRightTabIndex = 1
	InventoryRightTabCrafting   protocol.InventoryRightTabIndex = 2
	InventoryRightTabArmour     protocol.InventoryRightTabIndex = 3
)

// SetPlayerInventoryOptions is a bidirectional packet that can be used to update the inventory options of a
// player.
type SetPlayerInventoryOptions struct {
	// LeftInventoryTab is the tab that is selected on the left side of the inventory. This is usually for the
	// creative inventory. It is one of the InventoryLeftTab constants above.
	LeftInventoryTab protocol.InventoryLeftTabIndex
	// RightInventoryTab is the tab that is selected on the right side of the inventory. This is usually for the
	// player's own inventory. It is one of the InventoryRightTab constants above.
	RightInventoryTab protocol.InventoryRightTabIndex
	// Filtering is whether the player has enabled the filtering between recipes they have unlocked or not.
	Filtering bool
	// InventoryLayout is the layout of the inventory. It is one of the InventoryLayout constants above.
	LayoutInv protocol.InventoryLayout
	// CraftingLayout is the layout of the crafting inventory. It is one of the InventoryLayout constants above.
	LayoutCraft protocol.InventoryLayout
}

// ID returns the protocol ID for SetPlayerInventoryOptions.
func (*SetPlayerInventoryOptions) ID() uint32 { return IDSetPlayerInventoryOptions }

// Marshal reads or writes SetPlayerInventoryOptions using its canonical wire layout.
func (pk *SetPlayerInventoryOptions) Marshal(io protocol.IO) {
	pk.LeftInventoryTab.Marshal(io)
	pk.RightInventoryTab.Marshal(io)
	io.Bool(&pk.Filtering)
	pk.LayoutInv.Marshal(io)
	pk.LayoutCraft.Marshal(io)
}
