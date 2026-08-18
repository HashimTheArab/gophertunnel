package protocol

import "github.com/sandertv/gophertunnel/minecraft/nbt"

const (
	ItemEntryVersionLegacy = iota
	ItemEntryVersionDataDriven
	ItemEntryVersionNone
)

// ItemInstance represents a unique instance of an item stack. These instances carry a specific network ID
// that is persistent for the stack.
type ItemInstance struct {
	// StackNetworkID is the network ID of the item stack. If the stack is empty, 0 is always written for this
	// field. If not, the field should be set to 1 if the server authoritative inventories are disabled in the
	// StartGame packet, or to a unique stack ID if it is enabled.
	StackNetworkID int32
	// Stack is the actual item stack of the item instance.
	Stack ItemStack
}

// ItemStack represents an item instance/stack over network. It has a network ID and a metadata value that
// define its type.
type ItemStack struct {
	ItemType
	// BlockRuntimeID ...
	BlockRuntimeID int32
	// Count is the count of items that the item stack holds.
	Count uint16
	// NBTData is a map that is serialised to its NBT representation when sent in a packet.
	NBTData map[string]any
	// CanBePlacedOn is a list of block identifiers like 'minecraft:stone' which the item, if it is an item
	// that can be placed, can be placed on top of.
	CanBePlacedOn []string
	// CanBreak is a list of block identifiers like 'minecraft:dirt' that the item is able to break.
	CanBreak []string
	// BlockingTick is the tick at which a shield started blocking. It is only used for shield items.
	BlockingTick int64
}

// StackRequestItem is the descriptor-backed item format used by deprecated craft-result stack request actions.
// Unlike ordinary item stacks, it identifies the item by name instead of a numeric network ID.
type StackRequestItem struct {
	// Identifier is the namespaced item identifier, such as minecraft:stone.
	Identifier string
	// MetadataValue is the metadata value or damage value of the item.
	MetadataValue uint32
	// BlockRuntimeID is the runtime ID of the block represented by the item, if any.
	BlockRuntimeID int32
	// Count is the number of items in the stack.
	Count uint16
	// NBTData is the item's compound tag.
	NBTData map[string]any
	// CanBePlacedOn contains the block identifiers this item may be placed on.
	CanBePlacedOn []string
	// CanBreak contains the block identifiers this item may break.
	CanBreak []string
	// BlockingTick is the tick at which a shield started blocking.
	BlockingTick int64
}

type itemUserData struct {
	nbtData       map[string]any
	canBePlacedOn []string
	canBreak      []string
	blockingTick  int64
}

func itemStackUserData(x *ItemStack) itemUserData {
	return itemUserData{
		nbtData:       x.NBTData,
		canBePlacedOn: x.CanBePlacedOn,
		canBreak:      x.CanBreak,
		blockingTick:  x.BlockingTick,
	}
}

func stackRequestItemUserData(x *StackRequestItem) itemUserData {
	return itemUserData{
		nbtData:       x.NBTData,
		canBePlacedOn: x.CanBePlacedOn,
		canBreak:      x.CanBreak,
		blockingTick:  x.BlockingTick,
	}
}

// ItemType represents a consistent combination of network ID and metadata value of an item. It cannot usually
// be changed unless a new item is obtained.
type ItemType struct {
	// NetworkID is the numerical network ID of the item. This is sometimes a positive ID, and sometimes a
	// negative ID, depending on what item it concerns.
	NetworkID int32
	// MetadataValue is the metadata value of the item. For some items, this is the damage value, whereas for
	// other items it is simply an identifier of a variant of the item.
	MetadataValue uint32
}

// ItemEntry is an item sent in the StartGame item table. It holds a name and a legacy ID, which is used to
// point back to that name.
type ItemEntry struct {
	// Name if the name of the item, which is a name like 'minecraft:stick'.
	Name string
	// RuntimeID is the ID that is used to identify the item over network. After sending all items in the
	// StartGame packet, items will then be identified using these numerical IDs.
	RuntimeID int16
	// ComponentBased specifies if the item was created using components, meaning the item is a custom item.
	ComponentBased bool
	// Version is the version of the item entry which is used by the client to determine how to handle the
	// item entry. It is one of the constants above.
	Version int32
	// Data is a map containing the components and properties of the item, if the item is component based.
	Data map[string]any
}

// ItemSlotCapabilities contains the item-definition properties used by inventory container validation. ArmorSlot is
// absent when the item is not wearable and otherwise uses the player armor-container indexes head=0, chest=1,
// legs=2, feet=3 and body=4.
type ItemSlotCapabilities struct {
	AllowOffHand Optional[bool]
	ArmorSlot    Optional[uint8]
}

// SlotCapabilities returns the inventory slot capabilities explicitly declared by the item entry's component data.
// An absent field means the entry did not declare that capability.
func (x ItemEntry) SlotCapabilities() ItemSlotCapabilities {
	caps := ItemSlotCapabilities{}
	components, _ := x.Data["components"].(map[string]any)
	if properties, ok := components["item_properties"].(map[string]any); ok {
		if allow, ok := itemComponentBool(properties["allow_off_hand"]); ok {
			caps.AllowOffHand = Option(allow)
		}
	}
	if allow, ok := itemComponentBool(components["minecraft:allow_off_hand"]); ok {
		caps.AllowOffHand = Option(allow)
	} else if component, ok := components["minecraft:allow_off_hand"].(map[string]any); ok {
		if allow, ok := itemComponentBool(component["value"]); ok {
			caps.AllowOffHand = Option(allow)
		}
	}
	if wearable, ok := components["minecraft:wearable"].(map[string]any); ok {
		if slot, ok := wearableItemArmorSlot(wearable["slot"]); ok {
			caps.ArmorSlot = Option(slot)
		}
	}
	return caps
}

func itemComponentBool(value any) (bool, bool) {
	switch value := value.(type) {
	case bool:
		return value, true
	case uint8:
		return value != 0, true
	case int8:
		return value != 0, true
	case int32:
		return value != 0, true
	default:
		return false, false
	}
}

func wearableItemArmorSlot(value any) (uint8, bool) {
	if slot, ok := value.(string); ok {
		switch slot {
		case "slot.armor.head":
			return 0, true
		case "slot.armor.chest":
			return 1, true
		case "slot.armor.legs":
			return 2, true
		case "slot.armor.feet":
			return 3, true
		case "slot.armor.body":
			return 4, true
		}
	}
	var equipmentSlot int32
	switch value := value.(type) {
	case int32:
		equipmentSlot = value
	case uint32:
		equipmentSlot = int32(value)
	default:
		return 0, false
	}
	if equipmentSlot < 2 || equipmentSlot > 6 {
		return 0, false
	}
	return uint8(equipmentSlot - 2), true
}

// Marshal encodes/decodes an ItemEntry.
func (x *ItemEntry) Marshal(r IO) {
	r.String(&x.Name)
	r.Int16(&x.RuntimeID)
	r.Bool(&x.ComponentBased)
	r.Varint32(&x.Version)
	r.NBT(&x.Data, nbt.NetworkLittleEndian)
}

// MaterialReducerOutput is an output from a material reducer.
type MaterialReducerOutput struct {
	// NetworkID is the network ID of the output.
	NetworkID int32
	// Count is the quantity of the output.
	Count int32
}

// Marshal encodes/decodes a MaterialReducerOutput.
func (x *MaterialReducerOutput) Marshal(r IO) {
	r.Varint32(&x.NetworkID)
	r.Varint32(&x.Count)
}

// MaterialReducer is a craft in a material reducer block in education edition.
type MaterialReducer struct {
	// InputItem is the starting item.
	InputItem ItemType
	// Outputs contain all outputting items.
	Outputs []MaterialReducerOutput
}
