package minecraft

import (
	"context"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

func TestHandleResourcePackStackRetainsUnknownOptionalEntry(t *testing.T) {
	conn := testConn()
	conn.ctx = context.Background()
	conn.texturePacksRequired = true

	pk := &packet.ResourcePackStack{
		TexturePackRequired: false,
		TexturePacks: []protocol.StackResourcePack{{
			UUID: "6f733b6b-33f7-46a1-a246-588f130f51c2", Version: "1.2.3", SubPackName: "optional",
		}},
		BaseGameVersion:              "1.26.44",
		Experiments:                  []protocol.ExperimentData{{Name: "data_driven_items", Enabled: true}},
		ExperimentsPreviouslyToggled: true,
		IncludeEditorPacks:           true,
	}
	if err := conn.handleResourcePackStack(pk); err != nil {
		t.Fatalf("handle optional stack: %v", err)
	}

	snapshot, ok := conn.ResourcePackStack()
	if !ok {
		t.Fatal("optional stack snapshot was not retained")
	}
	entries := snapshot.Entries()
	if len(entries) != 1 {
		t.Fatalf("entry count = %d, want 1", len(entries))
	}
	entry := entries[0]
	if entry.Pack() != nil || entry.UUID() != pk.TexturePacks[0].UUID || entry.Version() != "1.2.3" || entry.SubPackName() != "optional" {
		t.Fatalf("unknown optional entry = (%v, %q, %q, %q)", entry.Pack(), entry.UUID(), entry.Version(), entry.SubPackName())
	}
	if !snapshot.Required() || snapshot.BaseGameVersion() != "1.26.44" ||
		len(snapshot.Experiments()) != 1 || !snapshot.ExperimentsPreviouslyToggled() || !snapshot.IncludeEditorPacks() {
		t.Fatalf("stack metadata was not retained: required=%t base=%q experiments=%#v toggled=%t editor=%t",
			snapshot.Required(), snapshot.BaseGameVersion(), snapshot.Experiments(),
			snapshot.ExperimentsPreviouslyToggled(), snapshot.IncludeEditorPacks())
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
	if _, ok := conn.ResourcePackStack(); ok {
		t.Fatal("failed required stack left a replayable snapshot")
	}
}
