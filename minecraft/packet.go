package minecraft

import (
	"bytes"
	"fmt"

	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// packetData holds the data of a Minecraft packet.
type packetData struct {
	h            *packet.Header
	full         []byte
	payload      *bytes.Buffer
	ownedFull    []byte
	ownedPayload []byte
	owned        bool
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

func (p *packetData) ensureOwned(pooled bool) *packetData {
	if p.owned {
		return p
	}
	payloadOffset := len(p.full) - p.payload.Len()
	var full []byte
	if pooled {
		full = acquireOwnedPacketBuffer(len(p.full))
		copy(full, p.full)
	} else {
		full = bytes.Clone(p.full)
	}
	p.ownedFull = full
	p.full = full[:len(full):len(full)]
	if payloadOffset < 0 {
		var payload []byte
		if pooled {
			payload = acquireOwnedPacketBuffer(p.payload.Len())
			copy(payload, p.payload.Bytes())
		} else {
			payload = bytes.Clone(p.payload.Bytes())
		}
		p.ownedPayload = payload
		resetPacketPayload(p.payload, payload[:len(payload):len(payload)])
	} else {
		resetPacketPayload(p.payload, full[payloadOffset:])
	}
	p.owned = true
	return p
}

// resetPacketPayload points payload at data without allocating another bytes.Buffer.
func resetPacketPayload(payload *bytes.Buffer, data []byte) {
	replacement := bytes.NewBuffer(data)
	*payload = *replacement
}

// release returns owned packet storage after all decoded values have copied their wire data.
func (p *packetData) release() {
	if !p.owned {
		return
	}
	releaseOwnedPacketBuffer(p.ownedFull)
	releaseOwnedPacketBuffer(p.ownedPayload)
	p.ownedFull = nil
	p.ownedPayload = nil
	p.owned = false
	p.full = nil
	p.payload.Reset()
}

// takeFull transfers the complete frame to a raw-byte caller instead of recycling it.
func (p *packetData) takeFull() []byte {
	if p.owned {
		releaseOwnedPacketBuffer(p.ownedPayload)
		p.ownedFull = nil
		p.ownedPayload = nil
		p.owned = false
	}
	return p.full[:len(p.full):len(p.full)]
}

// detachOwnedStorage prevents recycling storage that a custom reader may have retained in decoded output.
func (p *packetData) detachOwnedStorage() {
	p.ownedFull = nil
	p.ownedPayload = nil
	p.owned = false
}

// releasePacketData releases every retained packet in packets.
func releasePacketData(packets []*packetData) {
	for _, data := range packets {
		data.release()
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
	reuseInput := canReusePacketBuffers(conn.proto)
	defer func() {
		if reuseInput || err != nil || len(pks) == 0 {
			p.release()
		} else {
			p.detachOwnedStorage()
		}
	}()
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
