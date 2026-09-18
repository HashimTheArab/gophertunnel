package protocol

type DataItemType uint8

const (
	EntityDataTypeByte        DataItemType = 0
	EntityDataTypeInt16       DataItemType = 1
	EntityDataTypeInt32       DataItemType = 2
	EntityDataTypeFloat32     DataItemType = 3
	EntityDataTypeString      DataItemType = 4
	EntityDataTypeCompoundTag DataItemType = 5
	EntityDataTypeBlockPos    DataItemType = 6
	EntityDataTypeInt64       DataItemType = 7
	EntityDataTypeVec3        DataItemType = 8
)

// Marshal reads or writes DataItemType through its uint8 wire encoding.
func (x *DataItemType) Marshal(io IO) { io.Uint8((*uint8)(x)) }
