package minecraft

import (
	"context"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

func TestHandleResourcePackStackAllowsUnknownOptionalEntry(t *testing.T) {
	conn := testConn()
	conn.ctx = context.Background()

	err := conn.handleResourcePackStack(&packet.ResourcePackStack{
		TexturePackRequired: false,
		TexturePacks: []protocol.StackResourcePack{{
			UUID: "6f733b6b-33f7-46a1-a246-588f130f51c2", Version: "1.2.3", SubPackName: "optional",
		}},
	})
	if err != nil {
		t.Fatalf("handle optional stack: %v", err)
	}
}

func TestHandleResourcePackStackRejectsUnknownRequiredEntry(t *testing.T) {
	conn := testConn()
	conn.ctx = context.Background()

	err := conn.handleResourcePackStack(&packet.ResourcePackStack{
		TexturePackRequired: true,
		TexturePacks: []protocol.StackResourcePack{{
			UUID: "6f733b6b-33f7-46a1-a246-588f130f51c2", Version: "1.2.3",
		}},
	})
	if err == nil {
		t.Fatal("unknown required entry was accepted")
	}
}
