package minecraft

import (
	"bytes"
	"fmt"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// packetData holds the data of a Minecraft packet.
type packetData struct {
	h       *packet.Header
	full    []byte
	payload *bytes.Buffer
	owned   bool
}

// parseData parses packet bytes and reports the payload to the connection observer.
func parseData(data []byte, conn *Conn) (*packetData, error) {
	p, err := parsePacketData(data)
	if err != nil {
		return nil, err
	}
	if conn.packetFunc != nil {
		conn.packetFunc(*p.h, bytes.Clone(p.payload.Bytes()), conn.RemoteAddr(), conn.LocalAddr())
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
