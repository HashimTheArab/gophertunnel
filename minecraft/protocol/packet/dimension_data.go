package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// DimensionData is a packet sent from the server to the client containing information about data-driven
// dimensions that the server may have registered. This packet does not seem to be sent by default, rather
// only being sent when any data-driven dimensions are registered.
type DimensionData struct {
	// Definitions contain a list of data-driven dimension definitions registered on the server.
	Definitions []protocol.OrderedEntry[string, protocol.DimensionDefinition]
}

// Marshal reads or writes DimensionData using its canonical wire layout.
func (x *DimensionData) Marshal(io protocol.IO) {
	protocol.OrderedMap(io, &x.Definitions, io.Varuint32, func(value *string) {
		io.StringLimits(value, 0, 256)
	}, func(value *protocol.DimensionDefinition) {
		value.Marshal(io)
	})
}

// ID returns the protocol ID for DimensionData.
func (*DimensionData) ID() uint32 { return IDDimensionData }
