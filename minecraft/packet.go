package minecraft

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// packetData holds the data of a Minecraft packet.
type packetData struct {
	h       *packet.Header
	full    []byte
	payload *bytes.Buffer
	owned   bool
}

// RawPacket is one packet of a network batch read by Conn.ReadBatchRaw.
type RawPacket struct {
	// Data is the packet's header and payload exactly as received, owned by the caller.
	Data []byte
	// ID is the packet ID from the header.
	ID uint32
	// Decoded holds the packet decoded and converted to the latest protocol, when it was selected.
	Decoded []packet.Packet
}

// rawPacketID returns the packet ID of an encoded packet, or 0 if its header is malformed.
func rawPacketID(data []byte) uint32 {
	value, n := binary.Uvarint(data)
	if n <= 0 {
		return 0
	}
	return uint32(value) & 0x3ff
}

// decodeRawPayload decodes payload into pk with conn's protocol and converts it to the latest protocol.
func decodeRawPayload(conn *Conn, pk packet.Packet, payload []byte) (pks []packet.Packet, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("decode packet %T: %v", pk, recovered)
		}
	}()
	buf := bytes.NewBuffer(payload)
	pk.Marshal(conn.proto.NewReader(buf, conn.shieldID.Load(), conn.readerLimits))
	if buf.Len() != 0 {
		return nil, fmt.Errorf("decode packet %T: %v unread bytes left", pk, buf.Len())
	}
	return conn.proto.ConvertToLatest(pk, conn), nil
}

// parseData parses the packet data slice passed into a packetData struct.
func parseData(data []byte, conn *Conn) (*packetData, error) {
	buf := bytes.NewBuffer(data)
	header := &packet.Header{}
	if err := header.Read(buf); err != nil {
		// We don't return this as an error as it's not in the hand of the user to control this. Instead,
		// we return to reading a new packet.
		return nil, fmt.Errorf("read packet header: %w", err)
	}
	if conn.packetFunc != nil {
		// The packet func was set, so we call it.
		conn.packetFunc(*header, bytes.Clone(buf.Bytes()), conn.RemoteAddr(), conn.LocalAddr())
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

// decodePacket decodes p without applying connection-level disconnect policies.
func (p *packetData) decodePacket(conn *Conn) (pks []packet.Packet, err error) {
	// Attempt to fetch the packet with the right packet ID from the pool.
	pkFunc, ok := conn.pool[p.h.PacketID]
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

	r := conn.proto.NewReader(p.payload, conn.shieldID.Load(), conn.readerLimits)
	if translation := conn.actorIDs.Load(); translation != nil {
		r = translation.WrapReader(r)
	}
	pk.Marshal(r)
	if p.payload.Len() != 0 {
		err = fmt.Errorf("decode packet %T: %v unread bytes left: 0x%x", pk, p.payload.Len(), p.payload.Bytes())
	}
	if err != nil {
		return nil, err
	}
	return conn.proto.ConvertToLatest(pk, conn), err
}
