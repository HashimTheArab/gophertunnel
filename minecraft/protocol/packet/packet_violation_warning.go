package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

const (
	PacketViolationSeverityUnknown         protocol.PacketViolationSeverity = -1
	ViolationSeverityWarning               protocol.PacketViolationSeverity = 0
	ViolationSeverityFinalWarning          protocol.PacketViolationSeverity = 1
	ViolationSeverityTerminatingConnection protocol.PacketViolationSeverity = 2
)

// PacketViolationWarning is sent by the client when it receives an invalid packet from the server. It holds
// some information on the error that occurred. noinspection GoNameStartsWithPackageName
type PacketViolationWarning struct {
	Type     protocol.PacketViolationType
	Severity protocol.PacketViolationSeverity
	PacketID int32
	// ViolationContext holds a description on the violation of the packet.
	ViolationContext string
}

// Marshal reads or writes PacketViolationWarning using its canonical wire layout.
func (x *PacketViolationWarning) Marshal(io protocol.IO) {
	x.Type.Marshal(io)
	x.Severity.Marshal(io)
	io.Varint32(&x.PacketID)
	io.String(&x.ViolationContext)
}

// ID returns the protocol ID for PacketViolationWarning.
func (*PacketViolationWarning) ID() uint32 { return IDPacketViolationWarning }
