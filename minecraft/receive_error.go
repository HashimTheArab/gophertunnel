package minecraft

import (
	"encoding/binary"
	"fmt"
)

// ReceiveError retains a fatal receive cause without including packet data in its message.
type ReceiveError struct {
	stage string
	cause error
}

func (err *ReceiveError) Error() string {
	return fmt.Sprintf("receive %s: %T", err.stage, err.cause)
}

func (err *ReceiveError) Unwrap() error { return err.cause }

// ReceiveStage identifies whether batch decoding or packet handling failed.
func (err *ReceiveError) ReceiveStage() string { return err.stage }

type packetReceiveError struct {
	*ReceiveError
	id uint32
}

// PacketID returns the successfully parsed wire packet ID associated with this failure.
func (err *packetReceiveError) PacketID() uint32 { return err.id }

func packetReceiveCause(err error, data []byte) error {
	cause := &ReceiveError{stage: "packet", cause: err}
	if value, n := binary.Uvarint(data); n > 0 {
		return &packetReceiveError{ReceiveError: cause, id: uint32(value) & 0x3ff}
	}
	return cause
}

type receiveTerminal struct{ cause error }

// recordReceiveTerminal precedes teardown so a final flush cannot replace the receive failure.
func (conn *Conn) recordReceiveTerminal(err error) {
	if conn.ctx.Err() != nil && !conn.remoteTransportClosed() {
		return
	}
	conn.receiveTerminal.CompareAndSwap(nil, &receiveTerminal{cause: err})
}

func (conn *Conn) terminalCause(fallback error) error {
	if terminal := conn.receiveTerminal.Load(); terminal != nil {
		return terminal.cause
	}
	return fallback
}
