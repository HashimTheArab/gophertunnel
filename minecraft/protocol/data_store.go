package protocol

// DataStoreChange represents a change to a data store property value.
type DataStoreChange struct {
	// DataStoreName is the name of the data store.
	DataStoreName string
	// Property is the property that changed.
	Property string
	// UpdateCount is the update count.
	UpdateCount uint32
	// NewValue is the new property value.
	NewValue DynamicValue
}

func (*DataStoreChange) tagBedrockDDUI() uint32 { return 1 }

// Marshal reads or writes DataStoreChange using its canonical wire layout.
func (x *DataStoreChange) Marshal(io IO) {
	io.StringLimits(&x.DataStoreName, 1, 1000)
	io.StringLimits(&x.Property, 1, 1000)
	io.Uint32(&x.UpdateCount)
	Maximum(io, &x.UpdateCount, 4.294967294e+09)
	MarshalDynamicValue(io, &x.NewValue)
}
