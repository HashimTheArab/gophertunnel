package minecraft

import (
	"context"
	"errors"
)

func (conn *Conn) remoteTransportClosed() bool {
	if conn.ctx.Err() == nil {
		return false
	}
	var closeReason interface{ TransportCloseReason() string }
	return errors.As(context.Cause(conn.ctx), &closeReason) && closeReason.TransportCloseReason() == "remote_disconnect"
}

// waitRemoteReceiveDrain keeps a peer's transport notification behind accepted application data.
func (conn *Conn) waitRemoteReceiveDrain() error {
	if conn.receiveDone == nil || !conn.remoteTransportClosed() {
		return nil
	}
	select {
	case <-conn.receiveDone:
		return nil
	case <-conn.receiveDrainStop:
		return nil
	case <-conn.readDeadline:
		return context.DeadlineExceeded
	}
}

func (conn *Conn) stopReceiveDrain() {
	if conn.receiveDrainStop != nil && conn.receiveDrainStopped.CompareAndSwap(false, true) {
		close(conn.receiveDrainStop)
	}
}
