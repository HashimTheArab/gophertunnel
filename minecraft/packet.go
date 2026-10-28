package minecraft

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// packetData holds the data of a Minecraft packet.
type packetData struct {
	h       *packet.Header
	full    []byte
	payload *bytes.Buffer
	// owned specifies if full and payload no longer alias the Decoder's pooled batch buffer, meaning the
	// packetData may be retained after the read callback it was created in returns.
	owned bool
}

// RawPacket is one packet of a network batch read by Conn.ReadBatchRaw.
type RawPacket struct {
	// Data is the packet's header and payload exactly as received, owned by the caller.
	Data []byte
	// ID is the packet ID from the header.
	ID uint32
	// Decoded holds the packet decoded and converted to the latest protocol, when it was selected.
	Decoded []packet.Packet
	// DecodeErr is set when a selected packet could not be decoded. Decoded is then nil and Data is
	// still the packet as received, so the caller decides whether to pass it on.
	DecodeErr error
}

// rawPacketID returns the packet ID of an encoded packet, or 0 if its header is malformed.
func rawPacketID(data []byte) uint32 {
	value, n := binary.Uvarint(data)
	if n <= 0 {
		return 0
	}
	return uint32(value) & 0x3ff
}

// parseData parses packet bytes and reports the payload to the connection observer.
func parseData(data []byte, conn *Conn) (*packetData, error) {
	p, err := parsePacketData(data)
	if err != nil {
		return nil, err
	}
	if conn.observes(p.h.PacketID) {
		conn.observe(*p.h, bytes.Clone(p.payload.Bytes()), conn.RemoteAddr(), conn.LocalAddr())
	}
	return p, nil
}

// parsePacketData separates a packet header from its borrowed payload without connection policy.
func parsePacketData(data []byte) (*packetData, error) {
	buf := bytes.NewBuffer(data)
	header := &packet.Header{}
	if err := header.Read(buf); err != nil {
		return nil, fmt.Errorf("read packet header: %w", err)
	}
	return &packetData{h: header, full: data, payload: buf}, nil
}

// ensureOwned returns a packetData that owns its underlying data, copying it if it still aliases the
// Decoder's pooled batch buffer.
func (p *packetData) ensureOwned() *packetData {
	if p.owned {
		return p
	}
	full := bytes.Clone(p.full)
	payloadOffset := len(p.full) - p.payload.Len()
	var payload []byte
	if payloadOffset < 0 {
		payload = bytes.Clone(p.payload.Bytes())
	} else {
		payload = full[payloadOffset:]
	}
	return &packetData{
		h:       p.h,
		full:    full,
		payload: bytes.NewBuffer(payload),
		owned:   true,
	}
}

type unknownPacketError struct {
	id uint32
}

func (err unknownPacketError) Error() string {
	return fmt.Sprintf("unexpected packet (ID=%v)", err.id)
}

// decode decodes the packet payload held in the packetData and returns the packet.Packet decoded.
func (p *packetData) decode(conn *Conn) (pks []packet.Packet, err error) {
	if _, ok := conn.pool[p.h.PacketID]; !ok && conn.disconnectOnUnknownPacket {
		_ = conn.Close()
		return nil, unknownPacketError{id: p.h.PacketID}
	}
	pks, err = p.decodePacket(conn)
	if err != nil && conn.disconnectOnInvalidPacket {
		_ = conn.Close()
		return nil, err
	}
	return pks, err
}

// probe decodes a copy of p's payload, leaving p intact for delivery and applying no disconnect policies.
func (p *packetData) probe(conn *Conn) ([]packet.Packet, error) {
	return (&packetData{h: p.h, full: p.full, payload: bytes.NewBuffer(bytes.Clone(p.payload.Bytes())), owned: true}).decodePacket(conn)
}

// decodePacket decodes p without applying connection-level disconnect policies.
func (p *packetData) decodePacket(conn *Conn) ([]packet.Packet, error) {
	return p.decodeWith(conn.proto, conn.pool, conn.shieldID.Load(), conn.readerLimits, conn.actorIDs.Load(), conn)
}

// decodeWith shares packet decoding, unread-byte checks and conversion with codec-only callers.
func (p *packetData) decodeWith(proto Protocol, pool packet.Pool, shieldID int32, limits bool, translation *protocol.ActorIDTranslation, conn *Conn) (pks []packet.Packet, err error) {
	// Attempt to fetch the packet with the right packet ID from the pool.
	pkFunc, ok := pool[p.h.PacketID]
	var pk packet.Packet
	if !ok {
		// No packet with the ID. This may be a custom packet of some sorts.
		pk = &packet.Unknown{PacketID: p.h.PacketID}
	} else {
		pk = pkFunc()
	}

	defer func() {
		if recoveredErr := recover(); recoveredErr != nil {
			err = fmt.Errorf("decode packet %T: %w", pk, recoveredErr.(error))
		}
	}()

	r := proto.NewReader(p.payload, shieldID, limits)
	if translation != nil {
		r = translation.WrapReader(r)
	}
	pk.Marshal(r)
	if p.payload.Len() != 0 {
		err = fmt.Errorf("decode packet %T: %v unread bytes left: 0x%x", pk, p.payload.Len(), p.payload.Bytes())
	}
	if err != nil {
		return nil, err
	}
	return proto.ConvertToLatest(pk, conn), err
}

// DecodePacket decodes a current-protocol packet including its header, without connection-side
// observers or disconnect policy. pool selects the allowed packet direction; unregistered IDs
// become packet.Unknown. The connection's malformed-payload and unread-byte checks still apply.
func DecodePacket(data []byte, pool packet.Pool, shieldID int32, enableLimits bool) (packet.Packet, error) {
	p, err := parsePacketData(data)
	if err != nil {
		return nil, err
	}
	packets, err := p.decodeWith(DefaultProtocol, pool, shieldID, enableLimits, nil, nil)
	if err != nil {
		return nil, err
	}
	return packets[0], nil
}

// EncodePacket writes pk and its header to buf using proto and the current shield/actor context.
// It sets header.PacketID and returns the payload's offset in buf. Protocol conversion and write
// observation belong to the caller. A marshal panic leaves only buf changed, before publication.
func EncodePacket(buf *bytes.Buffer, header *packet.Header, pk packet.Packet, proto Protocol, shieldID int32, translation *protocol.ActorIDTranslation) int {
	header.PacketID = pk.ID()
	_ = header.Write(buf)
	payload := buf.Len()
	writer := proto.NewWriter(buf, shieldID)
	if translation != nil {
		writer = translation.WrapWriter(writer)
	}
	pk.Marshal(writer)
	return payload
}
