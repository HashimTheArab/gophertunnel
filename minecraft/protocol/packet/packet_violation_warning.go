package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	PacketViolationSeverityUnknown         protocol.PacketViolationSeverity = -1
	ViolationSeverityWarning               protocol.PacketViolationSeverity = 0
	ViolationSeverityFinalWarning          protocol.PacketViolationSeverity = 1
	ViolationSeverityTerminatingConnection protocol.PacketViolationSeverity = 2
)

// PacketViolationWarning is sent by the client when it receives an invalid packet from the server. It holds
// some information on the error that occurred. noinspection GoNameStartsWithPackageName
type PacketViolationWarning struct {
	// Type is the type of violation. It is one of the constants above.
	Type protocol.PacketViolationType
	// Severity specifies the severity of the packet violation. The action the client takes after this violation
	// depends on the severity sent.
	Severity protocol.PacketViolationSeverity
	// PacketID is the ID of the invalid packet that was received.
	PacketID int32
	// ViolationContext holds a description on the violation of the packet.
	ViolationContext string
}

// ID returns the protocol ID for PacketViolationWarning.
func (*PacketViolationWarning) ID() uint32 { return IDPacketViolationWarning }

// Marshal reads or writes PacketViolationWarning using its canonical wire layout.
func (pk *PacketViolationWarning) Marshal(io protocol.IO) {
	pk.Type.Marshal(io)
	pk.Severity.Marshal(io)
	io.Varint32(&pk.PacketID)
	io.String(&pk.ViolationContext)
}
