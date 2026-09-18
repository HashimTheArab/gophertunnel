package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// NetworkSettings is sent by the server to update a variety of network settings. These settings
// modify the way packets are sent over the network stack.
type NetworkSettings struct {
	// CompressionThreshold is the minimum size of a packet that is compressed when sent. If the size of
	// a packet is under this value, it is not compressed. When set to 0, all packets will be left
	// uncompressed.
	CompressionThreshold uint16
	// CompressionAlgorithm is the algorithm that is used to compress packets.
	CompressionAlgorithm protocol.PacketCompressionAlgorithm
	ClientThrottle       bool
	// ClientThrottleThreshold is the threshold for client throttling. If the number of players exceeds
	// this value, the client will throttle players.
	ClientThrottleThreshold uint8
	// ClientThrottleScalar is the scalar for client throttling. The scalar is the amount of players
	// that are ticked when throttling is enabled.
	ClientThrottleScalar float32
}

// Marshal reads or writes NetworkSettings using its canonical wire layout.
func (x *NetworkSettings) Marshal(io protocol.IO) {
	io.Uint16(&x.CompressionThreshold)
	x.CompressionAlgorithm.Marshal(io)
	io.Bool(&x.ClientThrottle)
	io.Uint8(&x.ClientThrottleThreshold)
	io.Float32(&x.ClientThrottleScalar)
}

// ID returns the protocol ID for NetworkSettings.
func (*NetworkSettings) ID() uint32 { return IDNetworkSettings }

const (
	CompressionAlgorithmFlate  protocol.PacketCompressionAlgorithm = 0
	CompressionAlgorithmSnappy protocol.PacketCompressionAlgorithm = 1
	CompressionAlgorithmNone   protocol.PacketCompressionAlgorithm = 65535
)
