package minecraft

import (
	"context"
	"reflect"
	"slices"
	"strings"
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
			stack := newResourcePackStackSnapshot(&packet.ResourcePackStack{TexturePackRequired: test.stackRequired, BaseGameVersion: "*"}, nil)
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
	stack := newResourcePackStackSnapshot(&packet.ResourcePackStack{
		TexturePackRequired: true,
		BaseGameVersion:     "1.26.50",
		TexturePacks: []protocol.StackResourcePack{
			{UUID: builtinID.String(), Version: "1.0.0", SubPackName: "sub"},
			{UUID: excludedID.String(), Version: "1.0.0", SubPackName: "sub"},
			{UUID: keptID.String(), Version: "1.0.0", SubPackName: "sub"},
			{UUID: ignoredID.String(), Version: "1.0.0", SubPackName: "sub"},
		},
	}, []*resource.Pack{excludedPack, keptPack})

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

// An invalid offer must fail before replacing the connection's previously configured offer or stack.
func TestConfigureResourcePackOfferSnapshotRejectsUnservableEntries(t *testing.T) {
	id := uuid.New()
	pack, err := resource.ReadBytes(testResourcePackArchive(t, id))
	if err != nil {
		t.Fatal(err)
	}
	info := packet.ResourcePacksInfo{TexturePacks: []protocol.TexturePackInfo{{UUID: id, Version: pack.Version(), Size: uint64(pack.Size())}}}
	valid := newResourcePackOfferSnapshot(&info, []*resource.Pack{pack})
	for _, missing := range []bool{false, true} {
		conn := testConn()
		conn.resourcePackOfferPreparing = true
		if err := conn.ConfigureResourcePackOfferSnapshot(valid, true); err != nil {
			t.Fatal(err)
		}
		stack := newResourcePackStackSnapshot(&packet.ResourcePackStack{BaseGameVersion: "*"}, nil)
		if err := conn.ConfigureResourcePackStack(stack, false); err != nil {
			t.Fatal(err)
		}
		previousOffer, previousStack := conn.resourcePackOffer, conn.resourcePackStack
		invalidInfo := *valid.packet()
		var packs []*resource.Pack
		if !missing {
			packs = []*resource.Pack{pack}
			invalidInfo.TexturePacks[0].Size++
		}
		invalid := newResourcePackOfferSnapshot(&invalidInfo, packs)
		if err := conn.ConfigureResourcePackOfferSnapshot(invalid, false); err == nil || !strings.Contains(err.Error(), "ProjectResourcePacks") {
			t.Fatalf("missing=%t: configure error = %v", missing, err)
		}
		if conn.resourcePackOffer != previousOffer || conn.resourcePackStack != previousStack || !conn.TexturePacksRequired() {
			t.Fatal("rejected offer changed connection state")
		}
		projected, _ := ProjectResourcePacks(invalid, stack, func(*resource.Pack) bool { return true })
		if err := conn.ConfigureResourcePackOfferSnapshot(projected, false); err != nil {
			t.Fatalf("projected offer rejected: %v", err)
		}
	}
}

// Snapshot packets preserve every wire field and isolate slices on input and output.
func TestResourcePackSnapshotsPreserveWireMetadata(t *testing.T) {
	id := uuid.New()
	info := packet.ResourcePacksInfo{
		TexturePackRequired: true, HasAddons: true, HasScripts: true, ForceDisableVibrantVisuals: true,
		WorldTemplateUUID: id, WorldTemplateVersion: "2.3.4",
		TexturePacks: []protocol.TexturePackInfo{{UUID: id, Version: "1.0.0", Size: 123, SubPackName: "sub", ContentKey: "key", ContentIdentity: "identity", DownloadURL: "https://example.test/pack", HasScripts: true, AddonPack: true, RTXEnabled: true}},
	}
	offer := newResourcePackOfferSnapshot(&info, nil)
	stackInfo := packet.ResourcePackStack{
		TexturePackRequired: true, BaseGameVersion: "1.26.50", ExperimentsPreviouslyToggled: true, IncludeEditorPacks: true,
		TexturePacks: []protocol.StackResourcePack{{UUID: id.String(), Version: "1.0.0", SubPackName: "sub"}},
		Experiments:  []protocol.ExperimentData{{Name: "experiment", Enabled: true}},
	}
	stack := newResourcePackStackSnapshot(&stackInfo, nil)
	if !reflect.DeepEqual(*offer.packet(), info) || !reflect.DeepEqual(*stack.packet(), stackInfo) {
		t.Fatal("snapshot lost wire metadata")
	}
	info.TexturePacks[0].Version = "changed"
	stackInfo.TexturePacks[0].SubPackName = "changed"
	stackInfo.Experiments[0].Name = "changed"
	offer.packet().TexturePacks[0].Version = "changed again"
	stack.packet().TexturePacks[0].SubPackName = "changed again"
	stack.packet().Experiments[0].Name = "changed again"
	stack.Experiments()[0].Name = "changed again"
	if offer.TexturePacks()[0].Info().Version != "1.0.0" || stack.Entries()[0].SubPackName() != "sub" || stack.Experiments()[0].Name != "experiment" {
		t.Fatal("snapshot aliases caller-owned packet slices")
	}
}

// Projection predicates receive a copy so their mutations cannot change the input snapshot.
func TestProjectResourcePacksIsolatesPredicateMutations(t *testing.T) {
	id := uuid.New()
	pack, err := resource.ReadBytes(testResourcePackArchive(t, id))
	if err != nil {
		t.Fatal(err)
	}
	offer := newResourcePackOfferSnapshot(&packet.ResourcePacksInfo{
		TexturePacks: []protocol.TexturePackInfo{{UUID: id, Version: pack.Version(), Size: uint64(pack.Size())}},
	}, []*resource.Pack{pack})
	original := pack.Modules()[0]
	projected, _ := ProjectResourcePacks(offer, ResourcePackStackSnapshot{}, func(pack *resource.Pack) bool {
		pack.Modules()[0].Type = "changed"
		return true
	})
	for _, snapshot := range []ResourcePackOfferSnapshot{offer, projected} {
		copy := snapshot.TexturePacks()[0].Pack()
		if copy.Modules()[0] != original {
			t.Fatal("predicate modified retained pack metadata")
		}
		copy.Modules()[0].Type = "changed again"
		if snapshot.Packs()[0].Modules()[0] != original {
			t.Fatal("pack accessor modified retained metadata")
		}
	}
}

// Every reference field added to either wire packet must remain isolated by its snapshot.
func TestResourcePackSnapshotsCopyAllPacketReferences(t *testing.T) {
	for _, original := range []packet.Packet{&packet.ResourcePacksInfo{}, &packet.ResourcePackStack{}} {
		value := reflect.ValueOf(original).Elem()
		for i := 0; i < value.NumField(); i++ {
			field := value.Field(i)
			switch field.Kind() {
			case reflect.Slice:
				field.Set(reflect.MakeSlice(field.Type(), 1, 1))
			case reflect.Pointer, reflect.Map, reflect.Interface:
				t.Fatalf("%T.%s needs snapshot ownership coverage", original, value.Type().Field(i).Name)
			}
		}
		var copied packet.Packet
		switch pk := original.(type) {
		case *packet.ResourcePacksInfo:
			copied = newResourcePackOfferSnapshot(pk, nil).packet()
		case *packet.ResourcePackStack:
			copied = newResourcePackStackSnapshot(pk, nil).packet()
		}
		clone := reflect.ValueOf(copied).Elem()
		for i := 0; i < value.NumField(); i++ {
			if field := value.Field(i); field.Kind() == reflect.Slice && field.Pointer() == clone.Field(i).Pointer() {
				t.Errorf("%T.%s shares snapshot storage", original, value.Type().Field(i).Name)
			}
		}
	}
}

// Every exempted pack is built in, matched only by its exact identity.
func TestIsBuiltinResourcePackMatchesTheExemptionList(t *testing.T) {
	for _, exempted := range exemptedPacks {
		if !IsBuiltinResourcePack(exempted.uuid, exempted.version) {
			t.Fatalf("exempted pack %s_%s is not built in", exempted.uuid, exempted.version)
		}
		if IsBuiltinResourcePack(exempted.uuid, exempted.version+".1") {
			t.Fatalf("another version of %s is built in", exempted.uuid)
		}
	}
	if IsBuiltinResourcePack("00112233-4455-6677-8899-aabbccddeeff", "1.0.0") {
		t.Fatal("a downloadable pack is built in")
	}
}
