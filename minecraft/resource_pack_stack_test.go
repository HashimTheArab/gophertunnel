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
	if snapshot.Required() || snapshot.BaseGameVersion() != "1.26.44" ||
		len(snapshot.Experiments()) != 1 || !snapshot.ExperimentsPreviouslyToggled() || !snapshot.IncludeEditorPacks() {
		t.Fatalf("stack metadata was not retained: required=%t base=%q experiments=%#v toggled=%t editor=%t",
			snapshot.Required(), snapshot.BaseGameVersion(), snapshot.Experiments(),
			snapshot.ExperimentsPreviouslyToggled(), snapshot.IncludeEditorPacks())
	}
	if !conn.TexturePacksRequired() {
		t.Fatal("effective required state did not retain ResourcePacksInfo requirement")
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

func TestConfigureResourcePackStackKeepsOfferAndStackRequiredBitsIndependent(t *testing.T) {
	for _, test := range []struct {
		name                         string
		offerRequired, stackRequired bool
	}{
		{name: "offer only", offerRequired: true},
		{name: "stack only", stackRequired: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn := testConn()
			conn.ctx = context.Background()
			conn.resourcePackOfferPreparing = true

			offer := newResourcePackOfferSnapshot(&packet.ResourcePacksInfo{TexturePackRequired: test.offerRequired}, nil)
			if err := conn.ConfigureResourcePackOfferSnapshot(offer, test.offerRequired); err != nil {
				t.Fatalf("configure offer: %v", err)
			}
			stack := newResourcePackStackSnapshot(nil, test.stackRequired, "*", nil, false, false)
			if err := conn.ConfigureResourcePackStack(stack, test.stackRequired); err != nil {
				t.Fatalf("configure stack: %v", err)
			}

			configuredOffer, ok := conn.ResourcePackOffer()
			if !ok || configuredOffer.TexturePackRequired() != test.offerRequired {
				t.Fatal("configuring stack changed ResourcePacksInfo required bit")
			}
			configuredStack, ok := conn.ResourcePackStack()
			if !ok || configuredStack.Required() != test.stackRequired {
				t.Fatal("configured ResourcePackStack required bit was not retained independently")
			}
			if !conn.TexturePacksRequired() {
				t.Fatal("effective required state did not combine offer and stack requirements")
			}

			if err := conn.handleResourcePackClientResponse(&packet.ResourcePackClientResponse{Response: packet.PackResponseAllPacksDownloaded}); err != nil {
				t.Fatalf("send configured stack: %v", err)
			}
			if len(conn.bufferedSend) != 1 {
				t.Fatalf("buffered packet count = %d, want 1", len(conn.bufferedSend))
			}
			data, err := parseData(conn.bufferedSend[0], conn)
			if err != nil {
				t.Fatalf("parse configured stack: %v", err)
			}
			var sent packet.ResourcePackStack
			sent.Marshal(protocol.NewReader(data.payload, 0, false))
			if sent.TexturePackRequired != test.stackRequired {
				t.Fatalf("replayed stack required = %t, want %t", sent.TexturePackRequired, test.stackRequired)
			}
		})
	}
}
