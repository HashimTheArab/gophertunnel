package protocol

type BedrockDDUIDataStoreUpdateData interface {
	Marshaler
	tagBedrockDDUIDataStoreUpdateData() uint32
}

// MarshalBedrockDDUIDataStoreUpdateData reads or writes the BedrockDDUIDataStoreUpdateData union using its canonical wire layout.
func MarshalBedrockDDUIDataStoreUpdateData(io IO, x *BedrockDDUIDataStoreUpdateData) {
	Union(io, x, io.Varuint32, BedrockDDUIDataStoreUpdateData.tagBedrockDDUIDataStoreUpdateData, func(tag uint32) BedrockDDUIDataStoreUpdateData {
		switch tag {
		case 0:
			return new(BedrockDDUIDataStoreUpdateDataDouble)
		case 1:
			return new(BedrockDDUIDataStoreUpdateDataBool)
		case 2:
			return new(BedrockDDUIDataStoreUpdateDataString)
		}
		return nil
	})
}

type BedrockDDUIDataStoreUpdateDataBool struct {
	Value bool
}

func (*BedrockDDUIDataStoreUpdateDataBool) tagBedrockDDUIDataStoreUpdateData() uint32 { return 1 }

// Marshal reads or writes BedrockDDUIDataStoreUpdateDataBool using its canonical wire layout.
func (x *BedrockDDUIDataStoreUpdateDataBool) Marshal(io IO) {
	io.Bool(&x.Value)
}

type BedrockDDUIDataStoreUpdateDataDouble struct {
	Value float64
}

func (*BedrockDDUIDataStoreUpdateDataDouble) tagBedrockDDUIDataStoreUpdateData() uint32 { return 0 }

// Marshal reads or writes BedrockDDUIDataStoreUpdateDataDouble using its canonical wire layout.
func (x *BedrockDDUIDataStoreUpdateDataDouble) Marshal(io IO) {
	io.Float64(&x.Value)
}

type BedrockDDUIDataStoreUpdateDataString struct {
	Value string
}

func (*BedrockDDUIDataStoreUpdateDataString) tagBedrockDDUIDataStoreUpdateData() uint32 { return 2 }

// Marshal reads or writes BedrockDDUIDataStoreUpdateDataString using its canonical wire layout.
func (x *BedrockDDUIDataStoreUpdateDataString) Marshal(io IO) {
	io.StringLimits(&x.Value, 0, 5000)
}

// Bitset131 stores the 131-bit value used by the wire bitset encoding.
type Bitset131 [3]uint64

const Bitset131Length = 131

// Set marks bit index i. It panics when i is outside [0, 131).
func (b *Bitset131) Set(i int) {
	if i < 0 || i >= Bitset131Length {
		panic("index out of bounds")
	}
	b[i/64] |= uint64(1) << uint(i%64)
}

// Unset clears bit index i. It panics when i is outside [0, 131).
func (b *Bitset131) Unset(i int) {
	if i < 0 || i >= Bitset131Length {
		panic("index out of bounds")
	}
	b[i/64] &^= uint64(1) << uint(i%64)
}

// Load reports whether bit index i is set. It panics when i is outside [0, 131).
func (b Bitset131) Load(i int) bool {
	if i < 0 || i >= Bitset131Length {
		panic("index out of bounds")
	}
	return b[i/64]&(uint64(1)<<uint(i%64)) != 0
}

// Len returns the number of bits in the bitset.
func (b Bitset131) Len() int { return Bitset131Length }

type DataItemEntryValue interface {
	Marshaler
	tagDataItemEntryValue() uint8
}

// MarshalDataItemEntryValue reads or writes the DataItemEntryValue union using its canonical wire layout.
func MarshalDataItemEntryValue(io IO, x *DataItemEntryValue) {
	Union(io, x, io.Uint8, DataItemEntryValue.tagDataItemEntryValue, func(tag uint8) DataItemEntryValue {
		switch tag {
		case 0:
			return new(NoiseAlignment)
		case 1:
			return new(DataItemShort)
		case 2:
			return new(DataItemInt)
		case 3:
			return new(DataItemFloat)
		case 4:
			return new(DataItemString)
		case 5:
			return new(DataItemCompoundTag)
		case 6:
			return new(DataItemPos)
		case 7:
			return new(DataItemInt64)
		case 8:
			return new(DataItemVec3)
		}
		return nil
	})
}

type DisconnectMessages interface {
	Marshaler
	tagDisconnectMessages() uint32
}

// MarshalDisconnectMessages reads or writes the DisconnectMessages union using its canonical wire layout.
func MarshalDisconnectMessages(io IO, x *DisconnectMessages) {
	Union(io, x, io.Varuint32, DisconnectMessages.tagDisconnectMessages, func(tag uint32) DisconnectMessages {
		switch tag {
		case 0:
			return new(DisconnectMessagesData)
		case 1:
			return new(DisconnectMessagesEmpty)
		}
		return nil
	})
}

type DisconnectMessagesEmpty struct {
}

func (*DisconnectMessagesEmpty) tagDisconnectMessages() uint32 { return 1 }

// Marshal reads or writes DisconnectMessagesEmpty using its canonical wire layout.
func (x *DisconnectMessagesEmpty) Marshal(io IO) {
}

type DynamicValueBool struct {
	Value bool
}

func (*DynamicValueBool) tagDynamicValue() int32 { return 1 }

// Marshal reads or writes DynamicValueBool using its canonical wire layout.
func (x *DynamicValueBool) Marshal(io IO) {
	io.Bool(&x.Value)
}

type DynamicValueDouble struct {
	Value float64
}

func (*DynamicValueDouble) tagDynamicValue() int32 { return 3 }

// Marshal reads or writes DynamicValueDouble using its canonical wire layout.
func (x *DynamicValueDouble) Marshal(io IO) {
	io.Float64(&x.Value)
}

type DynamicValueInt64 struct {
	Value int64
}

func (*DynamicValueInt64) tagDynamicValue() int32 { return 2 }

// Marshal reads or writes DynamicValueInt64 using its canonical wire layout.
func (x *DynamicValueInt64) Marshal(io IO) {
	io.Int64(&x.Value)
}

type DynamicValueList struct {
	Value []DynamicValue
}

func (*DynamicValueList) tagDynamicValue() int32 { return 5 }

// Marshal reads or writes DynamicValueList using its canonical wire layout.
func (x *DynamicValueList) Marshal(io IO) {
	FuncSlice(io, &x.Value, io.Varuint32, func(value *DynamicValue) {
		MarshalDynamicValue(io, value)
	})
}

type DynamicValueMap struct {
	Value []OrderedEntry[string, DynamicValue]
}

func (*DynamicValueMap) tagDynamicValue() int32 { return 6 }

// Marshal reads or writes DynamicValueMap using its canonical wire layout.
func (x *DynamicValueMap) Marshal(io IO) {
	OrderedMap(io, &x.Value, io.Varuint32, io.String, func(value *DynamicValue) {
		MarshalDynamicValue(io, value)
	})
}

type DynamicValueNone struct {
}

func (*DynamicValueNone) tagDynamicValue() int32 { return 0 }

// Marshal reads or writes DynamicValueNone using its canonical wire layout.
func (x *DynamicValueNone) Marshal(io IO) {
}

type DynamicValueString struct {
	Value string
}

func (*DynamicValueString) tagDynamicValue() int32 { return 4 }

// Marshal reads or writes DynamicValueString using its canonical wire layout.
func (x *DynamicValueString) Marshal(io IO) {
	io.String(&x.Value)
}

type GameRuleValue interface {
	Marshaler
	tagGameRuleValue() uint32
}

// MarshalGameRuleValue reads or writes the GameRuleValue union using its canonical wire layout.
func MarshalGameRuleValue(io IO, x *GameRuleValue) {
	Union(io, x, io.Varuint32, GameRuleValue.tagGameRuleValue, func(tag uint32) GameRuleValue {
		switch tag {
		case 0:
			return new(GameRuleValueEmpty)
		case 1:
			return new(GameRuleValueBool)
		case 2:
			return new(GameRuleValueInt32)
		case 3:
			return new(GameRuleValueFloat)
		}
		return nil
	})
}

type GameRuleValueBool struct {
	Value bool
}

func (*GameRuleValueBool) tagGameRuleValue() uint32 { return 1 }

// Marshal reads or writes GameRuleValueBool using its canonical wire layout.
func (x *GameRuleValueBool) Marshal(io IO) {
	io.Bool(&x.Value)
}

type GameRuleValueEmpty struct {
}

func (*GameRuleValueEmpty) tagGameRuleValue() uint32 { return 0 }

// Marshal reads or writes GameRuleValueEmpty using its canonical wire layout.
func (x *GameRuleValueEmpty) Marshal(io IO) {
}

type GameRuleValueFloat struct {
	Value float32
}

func (*GameRuleValueFloat) tagGameRuleValue() uint32 { return 3 }

// Marshal reads or writes GameRuleValueFloat using its canonical wire layout.
func (x *GameRuleValueFloat) Marshal(io IO) {
	io.Float32(&x.Value)
}

type GameRuleValueInt32 struct {
	Value int32
}

func (*GameRuleValueInt32) tagGameRuleValue() uint32 { return 2 }

// Marshal reads or writes GameRuleValueInt32 using its canonical wire layout.
func (x *GameRuleValueInt32) Marshal(io IO) {
	io.Int32(&x.Value)
}

type InventoryTransactionValue interface {
	Marshaler
	tagInventoryTransactionValue() uint32
}

// MarshalInventoryTransactionValue reads or writes the InventoryTransactionValue union using its canonical wire layout.
func MarshalInventoryTransactionValue(io IO, x *InventoryTransactionValue) {
	Union(io, x, io.Varuint32, InventoryTransactionValue.tagInventoryTransactionValue, func(tag uint32) InventoryTransactionValue {
		switch tag {
		case 0:
			return new(NormalTransactionData)
		case 1:
			return new(InventoryMismatchData)
		case 2:
			return new(ItemUseInventoryTransaction)
		case 3:
			return new(ItemUseOnActorInventoryTransaction)
		case 4:
			return new(ItemReleaseInventoryTransaction)
		}
		return nil
	})
}

type ServerBoundPackSettingChangePackSetting interface {
	Marshaler
	tagServerBoundPackSettingChangePackSetting() uint32
}

// MarshalServerBoundPackSettingChangePackSetting reads or writes the ServerBoundPackSettingChangePackSetting union using its canonical wire layout.
func MarshalServerBoundPackSettingChangePackSetting(io IO, x *ServerBoundPackSettingChangePackSetting) {
	Union(io, x, io.Varuint32, ServerBoundPackSettingChangePackSetting.tagServerBoundPackSettingChangePackSetting, func(tag uint32) ServerBoundPackSettingChangePackSetting {
		switch tag {
		case 0:
			return new(ServerBoundPackSettingChangePackSettingFloat)
		case 1:
			return new(ServerBoundPackSettingChangePackSettingBool)
		case 2:
			return new(ServerBoundPackSettingChangePackSettingString)
		}
		return nil
	})
}

type ServerBoundPackSettingChangePackSettingBool struct {
	Value bool
}

func (*ServerBoundPackSettingChangePackSettingBool) tagServerBoundPackSettingChangePackSetting() uint32 {
	return 1
}

// Marshal reads or writes ServerBoundPackSettingChangePackSettingBool using its canonical wire layout.
func (x *ServerBoundPackSettingChangePackSettingBool) Marshal(io IO) {
	io.Bool(&x.Value)
}

type ServerBoundPackSettingChangePackSettingFloat struct {
	Value float32
}

func (*ServerBoundPackSettingChangePackSettingFloat) tagServerBoundPackSettingChangePackSetting() uint32 {
	return 0
}

// Marshal reads or writes ServerBoundPackSettingChangePackSettingFloat using its canonical wire layout.
func (x *ServerBoundPackSettingChangePackSettingFloat) Marshal(io IO) {
	io.Float32(&x.Value)
}

type ServerBoundPackSettingChangePackSettingString struct {
	Value string
}

func (*ServerBoundPackSettingChangePackSettingString) tagServerBoundPackSettingChangePackSetting() uint32 {
	return 2
}

// Marshal reads or writes ServerBoundPackSettingChangePackSettingString using its canonical wire layout.
func (x *ServerBoundPackSettingChangePackSettingString) Marshal(io IO) {
	io.String(&x.Value)
}

type SetScoreEntriesItem interface {
	Marshaler
	tagSetScoreEntriesItem() uint8
}

// MarshalSetScoreEntriesItem reads or writes the SetScoreEntriesItem union using its canonical wire layout.
func MarshalSetScoreEntriesItem(io IO, x *SetScoreEntriesItem) {
	Union(io, x, io.Uint8, SetScoreEntriesItem.tagSetScoreEntriesItem, func(tag uint8) SetScoreEntriesItem {
		switch tag {
		case 0:
			return new(RemoveScore)
		case 1:
			return new(ChangePlayerScore)
		case 2:
			return new(ChangeEntityScore)
		case 3:
			return new(ChangeFakePlayerScore)
		}
		return nil
	})
}

type Shape interface {
	Marshaler
	tagShape() uint32
}

// MarshalShape reads or writes the Shape union using its canonical wire layout.
func MarshalShape(io IO, x *Shape) {
	Union(io, x, io.Varuint32, Shape.tagShape, func(tag uint32) Shape {
		switch tag {
		case 0:
			return new(ShapeEmpty)
		case 1:
			return new(ArrowShape)
		case 2:
			return new(TextShape)
		case 3:
			return new(BoxData)
		case 4:
			return new(LineData)
		case 5:
			return new(SphereData)
		case 6:
			return new(CylinderShape)
		case 7:
			return new(PyramidData)
		case 8:
			return new(EllipsoidShape)
		case 9:
			return new(ConeShape)
		}
		return nil
	})
}

type ShapeEmpty struct {
}

func (*ShapeEmpty) tagShape() uint32 { return 0 }

// Marshal reads or writes ShapeEmpty using its canonical wire layout.
func (x *ShapeEmpty) Marshal(io IO) {
}
