package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

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

// SetPlayerInventoryOptions is a bidirectional packet that can be used to update the inventory
// options of a player.
type SetPlayerInventoryOptions struct {
	InventoryOptions protocol.InventoryOptions
}

// Marshal reads or writes SetPlayerInventoryOptions using its canonical wire layout.
func (x *SetPlayerInventoryOptions) Marshal(io protocol.IO) {
	x.InventoryOptions.Marshal(io)
}

// ID returns the protocol ID for SetPlayerInventoryOptions.
func (*SetPlayerInventoryOptions) ID() uint32 { return IDSetPlayerInventoryOptions }
