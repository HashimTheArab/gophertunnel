package minecraft

import (
	"net"

	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// PacketObserver observes only the declared packet IDs of a Dialer connection, in both directions. It
// runs before PacketFunc at the same observation phase. Incoming payloads are
// owned copies shared with PacketFunc; changes do not affect packet decoding.
// Outgoing payloads have PacketFunc's existing temporary, mutable lifetime.
// Callbacks must not block. A nil Func or empty PacketIDs disables observation.
type PacketObserver struct {
	PacketIDs []uint32
	Func      func(header packet.Header, payload []byte, src, dst net.Addr)
}

type compiledPacketObserver struct {
	ids      map[uint32]struct{}
	callback func(packet.Header, []byte, net.Addr, net.Addr)
}

// compile copies the interests so changing the Dialer cannot reconfigure a Conn.
func (observer PacketObserver) compile() compiledPacketObserver {
	if observer.Func == nil || len(observer.PacketIDs) == 0 {
		return compiledPacketObserver{}
	}
	ids := make(map[uint32]struct{}, len(observer.PacketIDs))
	for _, id := range observer.PacketIDs {
		ids[id] = struct{}{}
	}
	return compiledPacketObserver{ids: ids, callback: observer.Func}
}

// forPacket returns the callback only when id was selected at dial time.
func (observer compiledPacketObserver) forPacket(id uint32) func(packet.Header, []byte, net.Addr, net.Addr) {
	if _, ok := observer.ids[id]; ok {
		return observer.callback
	}
	return nil
}
