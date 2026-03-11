package minecraft

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// packetData holds the data of a Minecraft packet.
type packetData struct {
	h       packet.Header
	full    []byte
	payload []byte
	offset  int
}

var packetDataPool = sync.Pool{
	New: func() any {
		return new(packetData)
	},
}

// parseData parses the packet data slice passed into a packetData struct.
func parseData(data []byte, conn *Conn) (*packetData, error) {
	pk := packetDataPool.Get().(*packetData)
	*pk = packetData{full: data, payload: data}
	if err := pk.h.Read(pk); err != nil {
		// We don't return this as an error as it's not in the hand of the user to control this. Instead,
		// we return to reading a new packet.
		releasePacketData(pk)
		return nil, fmt.Errorf("read packet header: %w", err)
	}
	if conn.packetFunc != nil {
		// The packet func was set, so we call it.
		conn.packetFunc(pk.h, pk.payload[pk.offset:], conn.RemoteAddr(), conn.LocalAddr())
	}
	pk.payload = pk.payload[pk.offset:]
	pk.offset = 0
	return pk, nil
}

func releasePacketData(pk *packetData) {
	*pk = packetData{}
	packetDataPool.Put(pk)
}

type unknownPacketError struct {
	id uint32
}

func (err unknownPacketError) Error() string {
	return fmt.Sprintf("unexpected packet (ID=%v)", err.id)
}

func (p *packetData) Read(b []byte) (int, error) {
	if p.offset >= len(p.payload) {
		return 0, io.EOF
	}
	n := copy(b, p.payload[p.offset:])
	p.offset += n
	return n, nil
}

func (p *packetData) ReadByte() (byte, error) {
	if p.offset >= len(p.payload) {
		return 0, io.EOF
	}
	b := p.payload[p.offset]
	p.offset++
	return b, nil
}

type convertToLatestInto interface {
	convertToLatestInto(pk packet.Packet, conn *Conn, dst []packet.Packet) []packet.Packet
}

type pooledReaderProtocol interface {
	acquireReader(r ByteReader, shieldID int32, enableLimits bool) protocol.IO
	releaseReader(r protocol.IO)
}

// decodeInto decodes the packet payload held in the packetData and appends the decoded packet(s) to dst.
func (p *packetData) decodeInto(conn *Conn, dst []packet.Packet) (pks []packet.Packet, err error) {
	// Attempt to fetch the packet with the right packet ID from the pool.
	pkFunc, ok := conn.pool[p.h.PacketID]
	var pk packet.Packet
	if !ok {
		// No packet with the ID. This may be a custom packet of some sorts.
		pk = &packet.Unknown{PacketID: p.h.PacketID}
		if conn.disconnectOnUnknownPacket {
			_ = conn.Close()
			return nil, unknownPacketError{id: p.h.PacketID}
		}
	} else {
		pk = pkFunc()
	}

	defer func() {
		if recoveredErr := recover(); recoveredErr != nil {
			err = fmt.Errorf("decode packet %T: %w", pk, recoveredErr.(error))
		}
		if err != nil && !errors.Is(err, unknownPacketError{}) && conn.disconnectOnInvalidPacket {
			_ = conn.Close()
		}
	}()

	p.offset = 0
	var r protocol.IO
	if pooledProto, ok := conn.proto.(pooledReaderProtocol); ok {
		r = pooledProto.acquireReader(p, conn.shieldID.Load(), conn.readerLimits)
		defer pooledProto.releaseReader(r)
	} else {
		r = conn.proto.NewReader(p, conn.shieldID.Load(), conn.readerLimits)
	}
	pk.Marshal(r)
	if unread := p.payload[p.offset:]; len(unread) != 0 {
		err = fmt.Errorf("decode packet %T: %v unread bytes left: 0x%x", pk, len(unread), unread)
	}
	if conn.disconnectOnInvalidPacket && err != nil {
		return nil, err
	}
	if converter, ok := conn.proto.(convertToLatestInto); ok {
		return converter.convertToLatestInto(pk, conn, dst), err
	}
	converted := conn.proto.ConvertToLatest(pk, conn)
	if len(dst) == 0 {
		return converted, err
	}
	return append(dst, converted...), err
}
