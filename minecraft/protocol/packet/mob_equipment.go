package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// MobEquipment is sent by the client to the server and the server to the client to make the other side aware
// of the new item that an entity is holding. It is used to show the item in the hand of entities such as
// zombies too.
type MobEquipment struct {
	TargetRuntimeID uint64
	// NewItem is the new item held after sending the MobEquipment packet. The entity will be shown holding that
	// item to the player it was sent to.
	NewItem protocol.NetworkItemStackDescriptorSerializedData
	// InventorySlot is the slot in the inventory that was held. This is the same as HotBarSlot, and only remains
	// for backwards compatibility.
	InventorySlot uint8
	// HotBarSlot is the slot in the hot bar that was held. It is the same as InventorySlot, which is only there
	// for backwards compatibility purposes.
	HotBarSlot uint8
	// WindowID is the window ID of the window that had its equipped item changed. This is usually the window ID
	// of the normal inventory, but may also be something else, for example with the off hand.
	WindowID uint8
}

// ID ...
func (*MobEquipment) ID() uint32 {
	return IDMobEquipment
}

func (pk *MobEquipment) Marshal(io protocol.IO) {
	io.ActorRuntimeID(&pk.TargetRuntimeID)
	pk.NewItem.Marshal(io)
	io.Uint8(&pk.InventorySlot)
	io.Uint8(&pk.HotBarSlot)
	io.Uint8(&pk.WindowID)
}
