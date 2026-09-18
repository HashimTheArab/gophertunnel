package protocol

// BedrockDDUIDataStoreChange represents a change to a data store property value.
type BedrockDDUIDataStoreChange struct {
	// DataStoreName is the name of the data store.
	DataStoreName string
	// Property is the property that changed.
	Property string
	// UpdateCount is the update count.
	UpdateCount uint32
	// NewValue is the new property value.
	NewValue DynamicValue
}

func (*BedrockDDUIDataStoreChange) tagBedrockDDUI() uint32 { return 1 }

// Marshal reads or writes BedrockDDUIDataStoreChange using its canonical wire layout.
func (x *BedrockDDUIDataStoreChange) Marshal(io IO) {
	io.StringLimits(&x.DataStoreName, 1, 1000)
	io.StringLimits(&x.Property, 1, 1000)
	io.Uint32(&x.UpdateCount)
	Maximum(io, &x.UpdateCount, 4.294967294e+09)
	MarshalDynamicValue(io, &x.NewValue)
}

type EducationEditionOffer uint32

const (
	DataStorePropertyTypeNone  EducationEditionOffer = 0
	DataStorePropertyTypeBool  EducationEditionOffer = 1
	DataStorePropertyTypeInt64 EducationEditionOffer = 2
)

// Marshal reads or writes EducationEditionOffer through its uint32 wire encoding.
func (x *EducationEditionOffer) Marshal(io IO) { io.Varuint32((*uint32)(x)) }

type ScoreboardIdentityPacketType uint8

const (
	DataStoreChangeTypeUpdate ScoreboardIdentityPacketType = 0
	DataStoreChangeTypeChange ScoreboardIdentityPacketType = 1
)

// Marshal reads or writes ScoreboardIdentityPacketType through its uint8 wire encoding.
func (x *ScoreboardIdentityPacketType) Marshal(io IO) { io.Uint8((*uint8)(x)) }
