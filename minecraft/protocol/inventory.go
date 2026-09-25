package protocol

type HandSlot uint8

const (
	HandSlotMainHand HandSlot = 0
	HandSlotOffHand  HandSlot = 1
)

// Marshal reads or writes HandSlot through its uint8 wire encoding.
func (x *HandSlot) Marshal(io IO) { io.Uint8((*uint8)(x)) }

// InventoryAction represents a single action that took place during an inventory transaction. On itself, this
// inventory action is always unbalanced: It must be combined with other actions in an inventory transaction
// to form a balanced transaction.
type InventoryAction struct {
	Source InventorySource
	// InventorySlot is the slot in which the action took place. Each action only describes the change of item in
	// a single slot.
	InventorySlot uint32
	FromItem      NetworkItemStackDescriptorSerializedData
	ToItem        NetworkItemStackDescriptorSerializedData
}

// Marshal reads or writes InventoryAction using its canonical wire layout.
func (x *InventoryAction) Marshal(io IO) {
	x.Source.Marshal(io)
	io.Varuint32(&x.InventorySlot)
	x.FromItem.Marshal(io)
	x.ToItem.Marshal(io)
}

type InventoryLayout int32

// Marshal reads or writes InventoryLayout through its int32 wire encoding.
func (x *InventoryLayout) Marshal(io IO) { io.Varint32((*int32)(x)) }

type InventoryLeftTabIndex int32

// Marshal reads or writes InventoryLeftTabIndex through its int32 wire encoding.
func (x *InventoryLeftTabIndex) Marshal(io IO) { io.Varint32((*int32)(x)) }

type InventoryMismatchData struct {
	Actions InventoryTransactionData
}

func (*InventoryMismatchData) tagInventoryTransactionPacketData() uint32 { return 1 }

// Marshal reads or writes InventoryMismatchData using its canonical wire layout.
func (x *InventoryMismatchData) Marshal(io IO) {
	x.Actions.Marshal(io)
}

type InventoryRightTabIndex int32

// Marshal reads or writes InventoryRightTabIndex through its int32 wire encoding.
func (x *InventoryRightTabIndex) Marshal(io IO) { io.Varint32((*int32)(x)) }

type InventorySource struct {
	SourceType  InventorySourceType
	ContainerID Optional[int8]
	BitFlags    Optional[InventorySourceInventorySourceFlags]
}

// Marshal reads or writes InventorySource using its canonical wire layout.
func (x *InventorySource) Marshal(io IO) {
	x.SourceType.Marshal(io)
	OptionalFunc(io, &x.ContainerID, io.Int8)
	OptionalMarshaler(io, &x.BitFlags)
}

type InventorySourceInventorySourceFlags uint32

const (
	InventorySourceInventorySourceFlagsNoFlag                 InventorySourceInventorySourceFlags = 0
	InventorySourceInventorySourceFlagsWorldInteractionRandom InventorySourceInventorySourceFlags = 1
)

// Marshal reads or writes InventorySourceInventorySourceFlags through its uint32 wire encoding.
func (x *InventorySourceInventorySourceFlags) Marshal(io IO) { io.Varuint32((*uint32)(x)) }

type InventorySourceType uint32

const (
	InventoryActionSourceContainer       InventorySourceType = 0
	InventoryActionSourceGlobalInventory InventorySourceType = 1
	InventoryActionSourceWorld           InventorySourceType = 2
	InventoryActionSourceCreative        InventorySourceType = 3
	InventoryActionSourceTODO            InventorySourceType = 99999
)

// Marshal reads or writes InventorySourceType through its uint32 wire encoding.
func (x *InventorySourceType) Marshal(io IO) { io.Varuint32((*uint32)(x)) }

// InventoryTransactionData represents an object that holds data specific to an inventory transaction type.
// The data it holds depends on the type.
type InventoryTransactionData struct {
	Actions []InventoryAction
}

// Marshal reads or writes InventoryTransactionData using its canonical wire layout.
func (x *InventoryTransactionData) Marshal(io IO) {
	Slice(io, &x.Actions)
}

type ItemReleaseInventoryTransactionActionType int32

const (
	ReleaseItemActionRelease ItemReleaseInventoryTransactionActionType = 0
	ReleaseItemActionConsume ItemReleaseInventoryTransactionActionType = 1
)

// Marshal reads or writes ItemReleaseInventoryTransactionActionType through its int32 wire encoding.
func (x *ItemReleaseInventoryTransactionActionType) Marshal(io IO) { io.Varint32((*int32)(x)) }

type ItemUseInventoryTransactionActionType int32

const (
	UseItemActionClickBlock  ItemUseInventoryTransactionActionType = 0
	UseItemActionClickAir    ItemUseInventoryTransactionActionType = 1
	UseItemActionBreakBlock  ItemUseInventoryTransactionActionType = 2
	UseItemActionUseAsAttack ItemUseInventoryTransactionActionType = 3
)

// Marshal reads or writes ItemUseInventoryTransactionActionType through its int32 wire encoding.
func (x *ItemUseInventoryTransactionActionType) Marshal(io IO) { io.Varint32((*int32)(x)) }

type ItemUseInventoryTransactionClientCooldownState uint8

const (
	ClientCooldownStateOff ItemUseInventoryTransactionClientCooldownState = 0
	ClientCooldownStateOn  ItemUseInventoryTransactionClientCooldownState = 1
)

// Marshal reads or writes ItemUseInventoryTransactionClientCooldownState through its uint8 wire encoding.
func (x *ItemUseInventoryTransactionClientCooldownState) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type ItemUseInventoryTransactionPredictedResult uint8

const (
	ClientPredictionFailure ItemUseInventoryTransactionPredictedResult = 0
	ClientPredictionSuccess ItemUseInventoryTransactionPredictedResult = 1
)

// Marshal reads or writes ItemUseInventoryTransactionPredictedResult through its uint8 wire encoding.
func (x *ItemUseInventoryTransactionPredictedResult) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type ItemUseInventoryTransactionTriggerType uint8

const (
	TriggerTypeUnknown        ItemUseInventoryTransactionTriggerType = 0
	TriggerTypePlayerInput    ItemUseInventoryTransactionTriggerType = 1
	TriggerTypeSimulationTick ItemUseInventoryTransactionTriggerType = 2
)

// Marshal reads or writes ItemUseInventoryTransactionTriggerType through its uint8 wire encoding.
func (x *ItemUseInventoryTransactionTriggerType) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type ItemUseOnActorInventoryTransactionActionType int32

const (
	UseItemOnEntityActionInteract     ItemUseOnActorInventoryTransactionActionType = 0
	UseItemOnEntityActionAttack       ItemUseOnActorInventoryTransactionActionType = 1
	UseItemOnEntityActionItemInteract ItemUseOnActorInventoryTransactionActionType = 2
)

// Marshal reads or writes ItemUseOnActorInventoryTransactionActionType through its int32 wire encoding.
func (x *ItemUseOnActorInventoryTransactionActionType) Marshal(io IO) { io.Varint32((*int32)(x)) }

// NormalTransactionData represents an inventory transaction data object for normal transactions, such as
// crafting. It has no content.
type NormalTransactionData struct {
	Actions InventoryTransactionData
}

func (*NormalTransactionData) tagInventoryTransactionPacketData() uint32 { return 0 }

// Marshal reads or writes NormalTransactionData using its canonical wire layout.
func (x *NormalTransactionData) Marshal(io IO) {
	x.Actions.Marshal(io)
}
