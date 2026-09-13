package packet

import (
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/nbt"
)

func TestAvailableActorIdentifiers_AddIdentifier(t *testing.T) {
	data, err := nbt.Marshal(map[string]any{"idlist": []any{map[string]any{"id": "minecraft:pig"}}})
	if err != nil {
		t.Fatal(err)
	}
	pk := &AvailableActorIdentifiers{SerialisedEntityIdentifiers: data}
	if err := pk.AddIdentifier("lunar:schematic_section"); err != nil {
		t.Fatal(err)
	}
	if err := pk.AddIdentifier("lunar:schematic_section"); err != nil {
		t.Fatal(err)
	}

	var root map[string]any
	if err := nbt.Unmarshal(pk.SerialisedEntityIdentifiers, &root); err != nil {
		t.Fatal(err)
	}
	identifiers, ok := root["idlist"].([]any)
	if !ok || len(identifiers) != 2 {
		t.Fatalf("idlist = %T %v, want two identifiers", root["idlist"], root["idlist"])
	}
	entry, ok := identifiers[1].(map[string]any)
	if !ok || entry["id"] != "lunar:schematic_section" {
		t.Fatalf("added identifier = %#v", identifiers[1])
	}
}

func TestAvailableActorIdentifiers_AddIdentifierRejectsInvalidNames(t *testing.T) {
	data, err := nbt.Marshal(map[string]any{"idlist": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, identifier := range []string{
		"lunar:foo:bar",
		"lunar:bad name",
		"Lunar:foo",
		"lunar:Upper",
		"lunar:",
		":foo",
	} {
		pk := &AvailableActorIdentifiers{SerialisedEntityIdentifiers: data}
		if err := pk.AddIdentifier(identifier); err == nil {
			t.Errorf("AddIdentifier(%q) succeeded, want validation error", identifier)
		}
	}
}
