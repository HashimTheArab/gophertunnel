package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// GameTestRequest ...
type GameTestRequest struct {
	// MaxTestsPerBatch ...
	MaxTestsPerBatch int32
	RepeatCount      int32
	// Rotation represents the rotation of the test. It is one of the constants above.
	Rotation      protocol.Rotation
	StopOnFailure bool
	TestPos       protocol.BlockPos
	// TestsPerRow ...
	TestsPerRow int32
	TestName    string
}

// ID ...
func (*GameTestRequest) ID() uint32 {
	return IDGameTestRequest
}

func (pk *GameTestRequest) Marshal(io protocol.IO) {
	io.Varint32(&pk.MaxTestsPerBatch)
	io.Varint32(&pk.RepeatCount)
	pk.Rotation.Marshal(io)
	io.Bool(&pk.StopOnFailure)
	pk.TestPos.Marshal(io)
	io.Varint32(&pk.TestsPerRow)
	io.String(&pk.TestName)
}
