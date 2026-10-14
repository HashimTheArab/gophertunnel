package minecraft

import (
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// The shield's runtime ID comes from the registry entry named minecraft:shield; a registry without one reports none.
func TestShieldRuntimeID(t *testing.T) {
	items := []protocol.ItemEntry{{Name: "minecraft:stone", RuntimeID: 1}, {Name: "minecraft:shield", RuntimeID: 355}}
	if id, ok := ShieldRuntimeID(items); !ok || id != 355 {
		t.Fatalf("ShieldRuntimeID() = %d, %v; want 355, true", id, ok)
	}
	if _, ok := ShieldRuntimeID(items[:1]); ok {
		t.Fatal("a registry without a shield reported one")
	}
}
