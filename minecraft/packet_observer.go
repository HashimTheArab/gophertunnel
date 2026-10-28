package minecraft

import (
	"fmt"
	"net"

	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// PacketObserver observes only the declared packet IDs of a Dialer connection, in both
// directions. It runs before PacketFunc at the same observation phase. Incoming payloads are
// owned copies shared with PacketFunc; changes do not affect packet decoding.
// Outgoing payloads have PacketFunc's existing temporary, mutable lifetime.
// Callbacks must not block. A nil Func or empty PacketIDs disables observation.
type PacketObserver struct {
	// PacketIDs must be below 1024, as packet headers hold 10-bit IDs; Dial rejects others.
	PacketIDs []uint32
	Func      func(header packet.Header, payload []byte, src, dst net.Addr)
}

// compiledPacketObserver is a PacketObserver whose IDs are a bitset indexed by packet ID.
type compiledPacketObserver struct {
	ids      [16]uint64
	callback func(packet.Header, []byte, net.Addr, net.Addr)
}

// compile copies the interests so changing the Dialer cannot reconfigure a Conn.
func (observer PacketObserver) compile() (compiledPacketObserver, error) {
	if observer.Func == nil || len(observer.PacketIDs) == 0 {
		return compiledPacketObserver{}, nil
	}
	compiled := compiledPacketObserver{callback: observer.Func}
	for _, id := range observer.PacketIDs {
		if id >= 1024 {
			return compiledPacketObserver{}, fmt.Errorf("PacketObserver: packet ID %d does not fit in a packet header", id)
		}
		compiled.ids[id>>6] |= 1 << (id & 63)
	}
	return compiled, nil
}

// observes reports whether id was selected.
func (observer *compiledPacketObserver) observes(id uint32) bool {
	return id < 1024 && observer.ids[id>>6]&(1<<(id&63)) != 0
}

// observes reports whether observe would call any callback for a packet with this ID.
func (conn *Conn) observes(id uint32) bool {
	return conn.packetFunc != nil || conn.packetObserver.observes(id)
}

// observe passes a packet to the PacketObserver, if it selected the ID, and then to PacketFunc. Callers
// check observes first, so unobserved packets cost no payload copy or address lookup.
func (conn *Conn) observe(header packet.Header, payload []byte, src, dst net.Addr) {
	if conn.packetObserver.observes(header.PacketID) {
		conn.packetObserver.callback(header, payload, src, dst)
	}
	if conn.packetFunc != nil {
		conn.packetFunc(header, payload, src, dst)
	}
}
