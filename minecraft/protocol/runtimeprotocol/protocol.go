// Package runtimeprotocol loads Mojang-style packet schemas into immutable
// minecraft.Protocol implementations.
package runtimeprotocol

import (
	"io/fs"

	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// Option changes how a Protocol is built from schemas.
type Option func(*loadConfig)

type loadConfig struct {
	fallback minecraft.Protocol
}

// WithFallback sets the protocol used for readers, writers, conversions, and
// packet constructors not covered by the loaded schemas.
func WithFallback(fallback minecraft.Protocol) Option {
	return func(c *loadConfig) {
		c.fallback = fallback
	}
}

// Protocol is an immutable minecraft.Protocol backed by loaded packet schemas.
type Protocol struct {
	id       int32
	version  string
	fallback minecraft.Protocol
	packets  map[uint32]*packetSpec
}

var _ minecraft.Protocol = (*Protocol)(nil)

// LoadMojangJSON loads all packet JSON files in fsys that match protocolID.
// Packet schemas are overlaid onto the fallback protocol's packet pools.
func LoadMojangJSON(fsys fs.FS, protocolID int32, opts ...Option) (*Protocol, error) {
	cfg := loadConfig{fallback: minecraft.DefaultProtocol}
	for _, opt := range opts {
		opt(&cfg)
	}
	return loadSchemas(fsys, protocolID, cfg)
}

// ID returns the network protocol ID represented by p.
func (p *Protocol) ID() int32 {
	return p.id
}

// Ver returns the Minecraft version string represented by p.
func (p *Protocol) Ver() string {
	return p.version
}

// Packets returns the fallback packet pool with loaded dynamic packet schemas
// overlaid by packet ID.
func (p *Protocol) Packets(listener bool) packet.Pool {
	pool := p.fallback.Packets(listener)
	for id, spec := range p.packets {
		if !spec.direction.allowed(listener) {
			continue
		}
		id, spec := id, spec
		pool[id] = func() packet.Packet {
			return &DynamicPacket{PacketID: id, Values: map[string]any{}, spec: spec}
		}
	}
	return pool
}

// NewReader returns a protocol reader for p. Runtime dynamic packets use the
// same primitive IO implementation as the fallback protocol.
func (p *Protocol) NewReader(r minecraft.ByteReader, shieldID int32, enableLimits bool) protocol.IO {
	return p.fallback.NewReader(r, shieldID, enableLimits)
}

// NewWriter returns a protocol writer for p. Runtime dynamic packets use the
// same primitive IO implementation as the fallback protocol.
func (p *Protocol) NewWriter(w minecraft.ByteWriter, shieldID int32) protocol.IO {
	return p.fallback.NewWriter(w, shieldID)
}

// ConvertToLatest keeps dynamic packets as-is and delegates compiled packets
// to the fallback protocol.
func (p *Protocol) ConvertToLatest(pk packet.Packet, conn *minecraft.Conn) []packet.Packet {
	if _, ok := pk.(*DynamicPacket); ok {
		return []packet.Packet{pk}
	}
	return p.fallback.ConvertToLatest(pk, conn)
}

// ConvertFromLatest keeps dynamic packets as-is and delegates compiled packets
// to the fallback protocol.
func (p *Protocol) ConvertFromLatest(pk packet.Packet, conn *minecraft.Conn) []packet.Packet {
	if _, ok := pk.(*DynamicPacket); ok {
		return []packet.Packet{pk}
	}
	return p.fallback.ConvertFromLatest(pk, conn)
}

// DynamicPacket is a schema-backed packet. Values contains decoded field values
// keyed by the field names used in the source schema.
type DynamicPacket struct {
	PacketID uint32
	Values   map[string]any

	spec *packetSpec
}

var _ packet.Packet = (*DynamicPacket)(nil)

// ID returns the packet ID for pk.
func (pk *DynamicPacket) ID() uint32 {
	return pk.PacketID
}

// Marshal reads or writes pk according to the schema it was created from.
func (pk *DynamicPacket) Marshal(io protocol.IO) {
	if pk.Values == nil {
		pk.Values = map[string]any{}
	}
	if pk.spec == nil {
		io.InvalidValue(pk.PacketID, "dynamic packet", "missing runtime packet schema")
		return
	}
	if _, ok := io.(*protocol.Reader); ok {
		pk.Values = pk.spec.decode(io)
		return
	}
	pk.spec.encode(io, pk.Values)
}

// Variant is the decoded or to-be-encoded value of a schema oneOf field.
type Variant struct {
	Index uint32
	Title string
	Value map[string]any
}
