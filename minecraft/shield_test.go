package minecraft

import (
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

func TestShieldRuntimeID(t *testing.T) {
	for _, tc := range []struct {
		name  string
		items []protocol.ItemEntry
		id    int32
		found bool
	}{
		{name: "empty registry"},
		{name: "absent", items: []protocol.ItemEntry{{Name: "minecraft:stone", RuntimeID: 1}}},
		{name: "present", items: []protocol.ItemEntry{{Name: "minecraft:stone", RuntimeID: 1}, {Name: "minecraft:shield", RuntimeID: 355}}, id: 355, found: true},
		{name: "zero runtime ID", items: []protocol.ItemEntry{{Name: "minecraft:shield"}}, found: true},
		{name: "last matching entry", items: []protocol.ItemEntry{{Name: "minecraft:shield", RuntimeID: 355}, {Name: "minecraft:shield", RuntimeID: 356}}, id: 356, found: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if id, found := ShieldRuntimeID(tc.items); id != tc.id || found != tc.found {
				t.Fatalf("ShieldRuntimeID() = %d, %v; want %d, %v", id, found, tc.id, tc.found)
			}
		})
	}
}

func TestConnObserveShieldPreservesPreviousIDWhenAbsent(t *testing.T) {
	conn := new(Conn)
	conn.shieldID.Store(355)
	conn.observeShield([]protocol.ItemEntry{{Name: "minecraft:stone", RuntimeID: 1}})
	if id := conn.shieldID.Load(); id != 355 {
		t.Fatalf("absent shield reset the observed runtime ID to %d", id)
	}
	conn.observeShield([]protocol.ItemEntry{{Name: "minecraft:shield", RuntimeID: 356}})
	if id := conn.shieldID.Load(); id != 356 {
		t.Fatalf("observed runtime ID = %d, want 356", id)
	}
}
