package minecraft

import (
	"bytes"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

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
