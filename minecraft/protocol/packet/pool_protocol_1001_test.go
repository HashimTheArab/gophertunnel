package packet

import (
	"bytes"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

func TestProtocol1001ServerPlayerPostMovePositionPacket(t *testing.T) {
	newPacket, ok := NewServerPool()[16]
	if !ok {
		t.Fatal("server packet ID 16 is not registered")
	}
	if _, ok := NewClientPool()[16]; ok {
		t.Fatal("server packet ID 16 is registered in the client pool")
	}

	want := []byte{
		0x00, 0x00, 0xc0, 0x3f,
		0x00, 0x00, 0x10, 0xc0,
		0x00, 0x00, 0x70, 0x40,
	}
	pk := newPacket()
	pk.Marshal(protocol.NewReader(bytes.NewBuffer(want), 0, true))

	var got bytes.Buffer
	pk.Marshal(protocol.NewWriter(&got, 0))
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("encoded packet = %x, want %x", got.Bytes(), want)
	}
}

func TestProtocol1001DeprecatedPacketsUnregistered(t *testing.T) {
	deprecated := []uint32{55, 117, 163, 173, 197}
	for _, pool := range []struct {
		name string
		pool Pool
	}{
		{name: "server", pool: NewServerPool()},
		{name: "client", pool: NewClientPool()},
	} {
		for _, id := range deprecated {
			if _, ok := pool.pool[id]; ok {
				t.Errorf("%s pool contains deprecated packet ID %d", pool.name, id)
			}
		}
	}
}
