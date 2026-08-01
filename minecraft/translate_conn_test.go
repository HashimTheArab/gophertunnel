package minecraft

import (
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// swapTranslation maps runtime ID 100 <-> 200.
func swapTranslation() *protocol.ActorIDTranslation {
	return &protocol.ActorIDTranslation{RuntimeID: func(id uint64) uint64 {
		switch id {
		case 100:
			return 200
		case 200:
			return 100
		}
		return id
	}}
}

func testConn() *Conn {
	return &Conn{proto: DefaultProtocol, pool: DefaultProtocol.Packets(true), hdr: &packet.Header{}}
}

func TestConnActorIDTranslationEncode(t *testing.T) {
	conn := testConn()
	conn.SetActorIDTranslation(swapTranslation())

	var dst [][]byte
	conn.encodePacketsTo(&dst, &packet.MovePlayer{EntityRuntimeID: 100})
	if len(dst) != 1 {
		t.Fatalf("expected 1 encoded packet, got %d", len(dst))
	}

	// Decoding through a connection without a translation must expose the translated ID.
	plain := testConn()
	data, err := parseData(dst[0], plain)
	if err != nil {
		t.Fatalf("parse encoded packet: %v", err)
	}
	pks, err := data.decode(plain)
	if err != nil {
		t.Fatalf("decode encoded packet: %v", err)
	}
	if got := pks[0].(*packet.MovePlayer).EntityRuntimeID; got != 200 {
		t.Errorf("runtime ID not translated on encode: %v", got)
	}
}

func TestConnActorIDTranslationDecode(t *testing.T) {
	plain := testConn()
	var dst [][]byte
	plain.encodePacketsTo(&dst, &packet.MovePlayer{EntityRuntimeID: 200})

	conn := testConn()
	conn.SetActorIDTranslation(swapTranslation())
	data, err := parseData(dst[0], conn)
	if err != nil {
		t.Fatalf("parse encoded packet: %v", err)
	}
	pks, err := data.decode(conn)
	if err != nil {
		t.Fatalf("decode encoded packet: %v", err)
	}
	if got := pks[0].(*packet.MovePlayer).EntityRuntimeID; got != 100 {
		t.Errorf("runtime ID not translated on decode: %v", got)
	}
}
