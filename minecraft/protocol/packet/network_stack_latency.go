package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// NetworkStackLatency is sent by the server (and the client, on development builds) to measure the latency
// over the entire Minecraft stack, rather than the RakNet latency. It has other usages too, such as the
// ability to be used as some kind of acknowledgement packet, to know when the client has received a certain
// other packet.
type NetworkStackLatency struct {
	Timestamp     uint64
	NeedsResponse bool
}

// Marshal reads or writes NetworkStackLatency using its canonical wire layout.
func (x *NetworkStackLatency) Marshal(io protocol.IO) {
	io.Uint64(&x.Timestamp)
	io.Bool(&x.NeedsResponse)
}

// ID returns the protocol ID for NetworkStackLatency.
func (*NetworkStackLatency) ID() uint32 { return IDNetworkStackLatency }
