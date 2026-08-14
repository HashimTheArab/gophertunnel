package clientstate

import (
	"testing"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

var testSelf = Self{RuntimeID: 1, UniqueID: 10}

// clearByType indexes ClearPackets output by packet type for assertions.
func clearByType(t *Tracker, self Self) map[string][]packet.Packet {
	byType := make(map[string][]packet.Packet)
	for _, pk := range t.ClearPackets(self) {
		var key string
		switch pk.(type) {
		case *packet.RemoveObjective:
			key = "objective"
		case *packet.RemoveActor:
			key = "actor"
		case *packet.PlayerList:
			key = "players"
		case *packet.BossEvent:
			key = "bossbar"
		case *packet.MobEffect:
			key = "effect"
		case *packet.ContainerClose:
			key = "container"
		default:
			key = "tail"
		}
		byType[key] = append(byType[key], pk)
	}
	return byType
}

// Every observed piece of state must come back out as exactly one removal.
func TestClearPacketsRoundTrip(t *testing.T) {
	tr := NewTracker()
	tr.Observe(&packet.SetDisplayObjective{ObjectiveName: "sidebar"}, testSelf)
	tr.Observe(&packet.AddActor{EntityUniqueID: 2, EntityRuntimeID: 2}, testSelf)
	tr.Observe(&packet.AddItemActor{EntityUniqueID: 3, EntityRuntimeID: 3}, testSelf)
	tr.Observe(&packet.AddPainting{EntityUniqueID: 4, EntityRuntimeID: 4}, testSelf)
	tr.Observe(&packet.BossEvent{BossEntityUniqueID: 5, EventType: packet.BossEventShow}, testSelf)
	tr.Observe(&packet.MobEffect{EntityRuntimeID: 1, EffectType: 9, Operation: packet.MobEffectAdd}, testSelf)
	tr.Observe(&packet.ContainerOpen{WindowID: 7, ContainerType: 0}, testSelf)

	byType := clearByType(tr, testSelf)
	if n := len(byType["objective"]); n != 1 {
		t.Errorf("objective removals: got %d, want 1", n)
	}
	if n := len(byType["actor"]); n != 3 {
		t.Errorf("actor removals: got %d, want 3", n)
	}
	if n := len(byType["bossbar"]); n != 1 {
		t.Errorf("boss bar removals: got %d, want 1", n)
	}
	if n := len(byType["effect"]); n != 1 {
		t.Errorf("effect removals: got %d, want 1", n)
	}
	if n := len(byType["container"]); n != 1 {
		t.Errorf("container closes: got %d, want 1", n)
	}
	effect := byType["effect"][0].(*packet.MobEffect)
	if effect.EntityRuntimeID != testSelf.RuntimeID || effect.Operation != packet.MobEffectRemove {
		t.Errorf("effect removal targets runtime ID %d op %d", effect.EntityRuntimeID, effect.Operation)
	}
	container := byType["container"][0].(*packet.ContainerClose)
	if container.WindowID != 7 || !container.ServerSide {
		t.Errorf("container close: got window %d serverSide %t", container.WindowID, container.ServerSide)
	}

	// The tracker reset: a second sweep carries only the unconditional tail.
	for key, packets := range clearByType(tr, testSelf) {
		if key != "tail" {
			t.Errorf("state survived reset: %d %s packets", len(packets), key)
		}
	}
}

// Server-removed state must not be removed a second time by the sweep.
func TestObserveRemovals(t *testing.T) {
	tr := NewTracker()
	tr.Observe(&packet.SetDisplayObjective{ObjectiveName: "sidebar"}, testSelf)
	tr.Observe(&packet.RemoveObjective{ObjectiveName: "sidebar"}, testSelf)
	tr.Observe(&packet.AddActor{EntityUniqueID: 2}, testSelf)
	tr.Observe(&packet.RemoveActor{EntityUniqueID: 2}, testSelf)
	tr.Observe(&packet.BossEvent{BossEntityUniqueID: 5, EventType: packet.BossEventShow}, testSelf)
	tr.Observe(&packet.BossEvent{BossEntityUniqueID: 5, EventType: packet.BossEventUnregisterPlayer}, testSelf)
	tr.Observe(&packet.MobEffect{EntityRuntimeID: 1, EffectType: 9, Operation: packet.MobEffectAdd}, testSelf)
	tr.Observe(&packet.MobEffect{EntityRuntimeID: 1, EffectType: 9, Operation: packet.MobEffectRemove}, testSelf)

	for key, packets := range clearByType(tr, testSelf) {
		if key != "tail" {
			t.Errorf("removed state still swept: %d %s packets", len(packets), key)
		}
	}
}

// The player's own entity, list entry and recognized UUID survive the sweep.
func TestSelfRetained(t *testing.T) {
	tr := NewTracker()
	selfUUID, otherUUID := uuid.MustParse("11111111-1111-1111-1111-111111111111"), uuid.MustParse("22222222-2222-2222-2222-222222222222")
	tr.Observe(&packet.PlayerList{Entries: []protocol.PlayerListEntry{
		{ActionType: protocol.PlayerListActionAdd, UUID: selfUUID, EntityUniqueID: testSelf.UniqueID},
		{ActionType: protocol.PlayerListActionAdd, UUID: otherUUID, EntityUniqueID: 2},
	}}, testSelf)
	tr.Observe(&packet.AddActor{EntityUniqueID: testSelf.UniqueID}, testSelf)

	byType := clearByType(tr, testSelf)
	if len(byType["actor"]) != 0 {
		t.Error("own actor swept")
	}
	list := byType["players"][0].(*packet.PlayerList)
	if len(list.Entries) != 1 || list.Entries[0].UUID != otherUUID {
		t.Errorf("player list removals: %v", list.Entries)
	}

	// The retained entry is still tracked, so a later sweep can remove others
	// without touching it.
	tr.Observe(&packet.PlayerList{Entries: []protocol.PlayerListEntry{
		{ActionType: protocol.PlayerListActionAdd, UUID: otherUUID, EntityUniqueID: 2},
	}}, testSelf)
	list = clearByType(tr, testSelf)["players"][0].(*packet.PlayerList)
	if len(list.Entries) != 1 || list.Entries[0].UUID != otherUUID {
		t.Errorf("player list removals after reset: %v", list.Entries)
	}
}

// A zero Self must not recognize a list entry or track effects.
func TestZeroSelfDisablesRecognition(t *testing.T) {
	tr := NewTracker()
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	tr.Observe(&packet.PlayerList{Entries: []protocol.PlayerListEntry{
		{ActionType: protocol.PlayerListActionAdd, UUID: id, EntityUniqueID: 0},
	}}, Self{})
	tr.Observe(&packet.MobEffect{EntityRuntimeID: 0, EffectType: 9, Operation: packet.MobEffectAdd}, Self{})

	byType := clearByType(tr, testSelf)
	if len(byType["effect"]) != 0 {
		t.Error("effect tracked without a known self")
	}
	list := byType["players"][0].(*packet.PlayerList)
	if len(list.Entries) != 1 || list.Entries[0].UUID != id {
		t.Errorf("entry recognized as self without a known self: %v", list.Entries)
	}
}

// AddPlayer with zero ability data falls back to the runtime ID, matching how
// RemoveActor will later identify the entity.
func TestAddPlayerUniqueIDFallback(t *testing.T) {
	tr := NewTracker()
	tr.Observe(&packet.AddPlayer{
		EntityRuntimeID: 42,
		UUID:            uuid.MustParse("11111111-1111-1111-1111-111111111111"),
	}, testSelf)
	actors := clearByType(tr, testSelf)["actor"]
	if len(actors) != 1 || actors[0].(*packet.RemoveActor).EntityUniqueID != 42 {
		t.Errorf("actor removals: %v", actors)
	}
}

// A client closing the container on its own must stop the sweep from closing it.
func TestObserveClientContainerClose(t *testing.T) {
	tr := NewTracker()
	tr.Observe(&packet.ContainerOpen{WindowID: 7}, testSelf)
	tr.ObserveClient(&packet.ContainerClose{WindowID: 7})
	if n := len(clearByType(tr, testSelf)["container"]); n != 0 {
		t.Errorf("container closes after client close: got %d, want 0", n)
	}

	// A close for a different window leaves the tracked container open.
	tr.Observe(&packet.ContainerOpen{WindowID: 7}, testSelf)
	tr.ObserveClient(&packet.ContainerClose{WindowID: 8})
	if n := len(clearByType(tr, testSelf)["container"]); n != 1 {
		t.Errorf("container closes after mismatched close: got %d, want 1", n)
	}
}

// Effects on other entities are the server's problem, not sweep state.
func TestMobEffectOtherEntityIgnored(t *testing.T) {
	tr := NewTracker()
	tr.Observe(&packet.MobEffect{EntityRuntimeID: 99, EffectType: 9, Operation: packet.MobEffectAdd}, testSelf)
	if n := len(clearByType(tr, testSelf)["effect"]); n != 0 {
		t.Errorf("effect removals: got %d, want 0", n)
	}
}

// An empty objective name is a slot clear, not a registration.
func TestEmptyObjectiveNameIgnored(t *testing.T) {
	tr := NewTracker()
	tr.Observe(&packet.SetDisplayObjective{ObjectiveName: ""}, testSelf)
	if n := len(clearByType(tr, testSelf)["objective"]); n != 0 {
		t.Errorf("objective removals: got %d, want 0", n)
	}
}

// Tracked must cover exactly the types Observe records.
func TestTrackedMatchesObserve(t *testing.T) {
	tracked := []packet.Packet{
		&packet.SetDisplayObjective{}, &packet.RemoveObjective{},
		&packet.AddActor{}, &packet.AddItemActor{}, &packet.AddPainting{}, &packet.AddPlayer{}, &packet.RemoveActor{},
		&packet.PlayerList{}, &packet.BossEvent{}, &packet.MobEffect{},
		&packet.ContainerOpen{}, &packet.ContainerClose{},
	}
	for _, pk := range tracked {
		if !Tracked(pk) {
			t.Errorf("Tracked(%T) = false", pk)
		}
	}
	if Tracked(&packet.MovePlayer{}) {
		t.Error("Tracked(*packet.MovePlayer) = true")
	}
}
