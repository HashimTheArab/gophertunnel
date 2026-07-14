package packet

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

func TestTextMessageLengthLimit(t *testing.T) {
	marshalText := func(length int) {
		var buf bytes.Buffer
		pk := &Text{TextType: TextTypeRaw, Message: strings.Repeat("a", length)}
		pk.Marshal(protocol.NewWriter(&buf, 0))
	}

	t.Run("maximum", func(t *testing.T) {
		marshalText(65536)
	})
	t.Run("over maximum", func(t *testing.T) {
		assertPanicContains(t, "string too long", func() {
			marshalText(65537)
		})
	})
}

func TestNetworkChunkPublisherUpdateSavedChunksLimit(t *testing.T) {
	assertPanicContains(t, "saved chunks exceeds maximum length", func() {
		var buf bytes.Buffer
		pk := &NetworkChunkPublisherUpdate{SavedChunks: make([]protocol.ChunkPos, 9217)}
		pk.Marshal(protocol.NewWriter(&buf, 0))
	})
}

func TestClientPoolIncludesUpdateBlock(t *testing.T) {
	newPacket, ok := NewClientPool()[IDUpdateBlock]
	if !ok {
		t.Fatal("client packet pool does not include UpdateBlock")
	}
	if _, ok := newPacket().(*UpdateBlock); !ok {
		t.Fatalf("IDUpdateBlock factory returned %T", newPacket())
	}
}

func assertPanicContains(t *testing.T, want string, f func()) {
	t.Helper()
	defer func() {
		got := recover()
		if got == nil {
			t.Fatalf("expected panic containing %q", want)
		}
		if message := fmt.Sprint(got); !strings.Contains(message, want) {
			t.Fatalf("panic = %q, want substring %q", message, want)
		}
	}()
	f()
}
