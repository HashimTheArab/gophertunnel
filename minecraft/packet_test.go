package minecraft

import (
	"bytes"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

func TestPacketCodec_CurrentPacketAndMalformedPayload(t *testing.T) {
	// SetTime(6000): packet ID 10 followed by signed-varint 6000.
	wire := []byte{0x0a, 0xe0, 0x5d}
	var encoded bytes.Buffer
	var header packet.Header
	if payload := EncodePacket(&encoded, &header, &packet.SetTime{Time: 6000}, DefaultProtocol, 0, nil); payload != 1 {
		t.Fatalf("payload offset = %d, want 1", payload)
	}
	if !bytes.Equal(encoded.Bytes(), wire) {
		t.Fatalf("encoded = %x, want %x", encoded.Bytes(), wire)
	}
	pool := DefaultProtocol.Packets(false)
	pk, err := DecodePacket(wire, pool, 0, true)
	setTime, ok := pk.(*packet.SetTime)
	if err != nil || !ok || setTime.Time != 6000 {
		t.Fatalf("decoded = %#v, %v", pk, err)
	}
	for _, malformed := range [][]byte{{0x80}, {0x0a}, append(bytes.Clone(wire), 0xaa, 0xbb)} {
		if pk, err := DecodePacket(malformed, pool, 0, true); err == nil || pk != nil {
			t.Fatalf("malformed %x decoded as %#v, %v", malformed, pk, err)
		}
	}
}

func TestPacketCodec_UnknownPayload(t *testing.T) {
	wire := []byte{0xff, 0x07, 0xaa, 0xbb}
	pk, err := DecodePacket(wire, DefaultProtocol.Packets(false), 0, true)
	if err != nil {
		t.Fatal(err)
	}
	unknown, ok := pk.(*packet.Unknown)
	if !ok || unknown.PacketID != 1023 || !bytes.Equal(unknown.Payload, []byte{0xaa, 0xbb}) {
		t.Fatalf("unknown packet = %#v", pk)
	}
}
