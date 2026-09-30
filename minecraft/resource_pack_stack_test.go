package minecraft

import (
	"context"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/resource"

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

// Projection keeps offer metadata and order, sizes kept entries by their content, and drops only the stack
// entries of dropped offer entries.
func TestProjectResourcePacksKeepsMetadataAndOrder(t *testing.T) {
	keptID, excludedID, ignoredID, builtinID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	keptPack, err := resource.ReadBytes(testResourcePackArchive(t, keptID))
	if err != nil {
		t.Fatal(err)
	}
	excludedPack, err := resource.ReadBytes(testResourcePackArchive(t, excludedID))
	if err != nil {
		t.Fatal(err)
	}
	info := &packet.ResourcePacksInfo{
		TexturePackRequired: true, HasScripts: true, WorldTemplateVersion: "1.2.3",
		TexturePacks: []protocol.TexturePackInfo{
			{UUID: excludedID, Version: "1.0.0", Size: uint64(excludedPack.Size())},
			{UUID: keptID, Version: "1.0.0", Size: 1, ContentKey: "key", DownloadURL: "https://cdn.example/p", AddonPack: true},
			{UUID: ignoredID, Version: "1.0.0", Size: 5},
		},
	}
	offer := newResourcePackOfferSnapshot(info, []*resource.Pack{excludedPack, keptPack})
	entry := func(id uuid.UUID, pack *resource.Pack) ResourcePackStackEntry {
		return ResourcePackStackEntry{uuid: id.String(), version: "1.0.0", pack: pack, subPackName: "sub"}
	}
	stack := newResourcePackStackSnapshot([]ResourcePackStackEntry{
		entry(builtinID, nil), entry(excludedID, excludedPack), entry(keptID, keptPack), entry(ignoredID, nil),
	}, true, "1.26.50", nil, false, false)

	projectedOffer, projectedStack := ProjectResourcePacks(offer, stack, func(pack *resource.Pack) bool { return pack.UUID() == keptID })

	entries := projectedOffer.TexturePacks()
	if len(entries) != 1 || !projectedOffer.HasScripts() || !projectedOffer.TexturePackRequired() || projectedOffer.WorldTemplateVersion() != "1.2.3" {
		t.Fatalf("projected offer = %+v", projectedOffer)
	}
	want := info.TexturePacks[1]
	want.Size = uint64(keptPack.Size())
	if got := entries[0].Info(); got != want || entries[0].Pack() == nil {
		t.Fatalf("kept entry = %+v, want %+v with content", got, want)
	}
	var ids []string
	for _, entry := range projectedStack.Entries() {
		ids = append(ids, entry.UUID())
	}
	if !slices.Equal(ids, []string{builtinID.String(), keptID.String()}) || !projectedStack.Required() || projectedStack.BaseGameVersion() != "1.26.50" {
		t.Fatalf("projected stack ids = %v required=%t", ids, projectedStack.Required())
	}
	if len(offer.TexturePacks()) != 3 || len(stack.Entries()) != 4 {
		t.Fatal("projection modified its inputs")
	}
}
