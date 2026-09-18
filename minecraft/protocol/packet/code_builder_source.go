package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	CodeBuilderStatusNone       protocol.CodeBuilderExecutionStateCodeStatus = 0
	CodeBuilderStatusNotStarted protocol.CodeBuilderExecutionStateCodeStatus = 1
	CodeBuilderStatusInProgress protocol.CodeBuilderExecutionStateCodeStatus = 2
	CodeBuilderStatusPaused     protocol.CodeBuilderExecutionStateCodeStatus = 3
	CodeBuilderStatusError      protocol.CodeBuilderExecutionStateCodeStatus = 4
	CodeBuilderStatusSucceeded  protocol.CodeBuilderExecutionStateCodeStatus = 5
)

const (
	CodeBuilderCategoryNone          protocol.CodeBuilderStorageQueryOptionsCategory = 0
	CodeBuilderCategoryStatus        protocol.CodeBuilderStorageQueryOptionsCategory = 1
	CodeBuilderCategoryInstantiation protocol.CodeBuilderStorageQueryOptionsCategory = 2
)

const (
	CodeBuilderOperationNone  protocol.CodeBuilderStorageQueryOptionsOperation = 0
	CodeBuilderOperationGet   protocol.CodeBuilderStorageQueryOptionsOperation = 1
	CodeBuilderOperationSet   protocol.CodeBuilderStorageQueryOptionsOperation = 2
	CodeBuilderOperationReset protocol.CodeBuilderStorageQueryOptionsOperation = 3
)

// CodeBuilderSource is an Education Edition packet sent by the client to the server to run an operation with
// a code builder.
type CodeBuilderSource struct {
	// Operation is used to distinguish the operation performed. It is always one of the constants listed above.
	Operation protocol.CodeBuilderStorageQueryOptionsOperation
	// Category is used to distinguish the category of the operation performed. It is always one of the constants
	// listed above.
	Category protocol.CodeBuilderStorageQueryOptionsCategory
	// CodeStatus is the status of the code builder. It is always one of the constants listed above.
	CodeStatus protocol.CodeBuilderExecutionStateCodeStatus
}

// ID returns the protocol ID for CodeBuilderSource.
func (*CodeBuilderSource) ID() uint32 { return IDCodeBuilderSource }

// Marshal reads or writes CodeBuilderSource using its canonical wire layout.
func (pk *CodeBuilderSource) Marshal(io protocol.IO) {
	pk.Operation.Marshal(io)
	pk.Category.Marshal(io)
	pk.CodeStatus.Marshal(io)
}
