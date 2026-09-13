// Package clientstate tracks the client-visible state a server builds up on a
// connection, so a proxy swapping that server out can take it back off the client.
package clientstate

import (
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// Self identifies the connection's own player entity. A zero Self disables
// self recognition.
type Self struct {
	RuntimeID uint64
	UniqueID  int64
}

// Tracker mirrors the client-visible state delivered to a client so a server
// swap can remove it. The caller synchronizes Observe against ClearPackets.
type Tracker struct {
	// objectives survive display-slot changes; only RemoveObjective drops one.
	objectives map[string]struct{}
	actors     map[int64]struct{}
	// players maps list entries to entity unique IDs, for AddPlayer packets
	// whose ability data carries none.
	players           map[uuid.UUID]int64
	bossBars          map[int64]struct{}
	effects           map[int32]struct{}
	volumes           map[uint32]int32
	containerOpen     bool
	containerWindowID byte
	containerType     byte
	// selfUUID is the player's own list entry, recognized by unique ID; the
	// entry and this field survive ClearPackets.
	selfUUID uuid.UUID
}

// NewTracker returns an empty Tracker.
func NewTracker() *Tracker {
	return &Tracker{
		objectives: make(map[string]struct{}),
		actors:     make(map[int64]struct{}),
		players:    make(map[uuid.UUID]int64),
		bossBars:   make(map[int64]struct{}),
		effects:    make(map[int32]struct{}),
		volumes:    make(map[uint32]int32),
	}
}

// Tracked reports whether Observe records pk, letting a hot path skip
// synchronization for packet types the Tracker ignores.
func Tracked(pk packet.Packet) bool {
	switch pk.(type) {
	case *packet.SetDisplayObjective, *packet.RemoveObjective,
		*packet.AddActor, *packet.AddItemActor, *packet.AddPainting, *packet.AddPlayer, *packet.RemoveActor,
		*packet.PlayerList, *packet.BossEvent, *packet.MobEffect,
		*packet.AddVolumeEntity, *packet.RemoveVolumeEntity,
		*packet.ContainerOpen, *packet.ContainerClose:
		return true
	default:
		return false
	}
}

// Observe records the state pk creates or removes. Observe only packets that
// were delivered: ClearPackets must target what the client really holds.
func (t *Tracker) Observe(pk packet.Packet, self Self) {
	switch pk := pk.(type) {
	case *packet.SetDisplayObjective:
		if pk.ObjectiveName != "" {
			t.objectives[pk.ObjectiveName] = struct{}{}
		}
	case *packet.RemoveObjective:
		delete(t.objectives, pk.ObjectiveName)
	case *packet.AddActor:
		t.actors[pk.EntityUniqueID] = struct{}{}
	case *packet.AddItemActor:
		t.actors[pk.EntityUniqueID] = struct{}{}
	case *packet.AddPainting:
		t.actors[pk.EntityUniqueID] = struct{}{}
	case *packet.AddPlayer:
		id := pk.AbilityData.EntityUniqueID
		if id == 0 {
			if listID := t.players[pk.UUID]; listID != 0 {
				id = listID
			} else {
				id = int64(pk.EntityRuntimeID)
			}
		}
		t.actors[id] = struct{}{}
		t.players[pk.UUID] = id
	case *packet.RemoveActor:
		delete(t.actors, pk.EntityUniqueID)
	case *packet.PlayerList:
		for _, entry := range pk.Entries {
			if entry.ActionType == protocol.PlayerListActionAdd {
				t.players[entry.UUID] = entry.EntityUniqueID
				if self != (Self{}) && entry.EntityUniqueID == self.UniqueID {
					t.selfUUID = entry.UUID
				}
			} else {
				delete(t.players, entry.UUID)
			}
		}
	case *packet.BossEvent:
		if pk.EventType == packet.BossEventHide || pk.EventType == packet.BossEventUnregisterPlayer {
			delete(t.bossBars, pk.BossEntityUniqueID)
		} else {
			t.bossBars[pk.BossEntityUniqueID] = struct{}{}
		}
	case *packet.MobEffect:
		if self == (Self{}) || pk.EntityRuntimeID != self.RuntimeID {
			break
		}
		if pk.Operation == packet.MobEffectRemove {
			delete(t.effects, pk.EffectType)
		} else {
			t.effects[pk.EffectType] = struct{}{}
		}
	case *packet.AddVolumeEntity:
		t.volumes[pk.EntityRuntimeID] = pk.Dimension
	case *packet.RemoveVolumeEntity:
		delete(t.volumes, pk.EntityRuntimeID)
	case *packet.ContainerOpen:
		t.containerOpen = true
		t.containerWindowID, t.containerType = pk.WindowID, pk.ContainerType
	case *packet.ContainerClose:
		t.closeContainer(pk.WindowID)
	}
}

// ObserveClient records client-authored state changes: a client closing the
// open container on its own.
func (t *Tracker) ObserveClient(pk packet.Packet) {
	if closed, ok := pk.(*packet.ContainerClose); ok {
		t.closeContainer(closed.WindowID)
	}
}

func (t *Tracker) closeContainer(windowID byte) {
	if t.containerOpen && t.containerWindowID == windowID {
		t.containerOpen = false
	}
}

// ClearPackets returns packets taking every piece of tracked state off the
// client, plus what no packet announces: titles, an open form, the inventory.
// The player's own entity and list entry are retained; the Tracker resets.
func (t *Tracker) ClearPackets(self Self) []packet.Packet {
	packets := make(
		[]packet.Packet, 0,
		len(t.objectives)+len(t.actors)+len(t.bossBars)+len(t.effects)+len(t.volumes)+8,
	)
	for name := range t.objectives {
		packets = append(packets, &packet.RemoveObjective{ObjectiveName: name})
	}
	for id := range t.actors {
		if self != (Self{}) && id == self.UniqueID {
			continue
		}
		packets = append(packets, &packet.RemoveActor{EntityUniqueID: id})
	}
	if len(t.players) > 0 {
		entries := make([]protocol.PlayerListEntry, 0, len(t.players))
		for id := range t.players {
			if id == t.selfUUID {
				continue
			}
			entries = append(entries, protocol.PlayerListEntry{ActionType: protocol.PlayerListActionRemove, UUID: id})
		}
		if len(entries) > 0 {
			packets = append(packets, &packet.PlayerList{Entries: entries})
		}
	}
	for id := range t.bossBars {
		packets = append(packets, &packet.BossEvent{BossEntityUniqueID: id, EventType: packet.BossEventHide})
	}
	for effect := range t.effects {
		packets = append(packets, &packet.MobEffect{
			EntityRuntimeID: self.RuntimeID,
			EffectType:      effect,
			Operation:       packet.MobEffectRemove,
		})
	}
	for id, dimension := range t.volumes {
		packets = append(packets, &packet.RemoveVolumeEntity{EntityRuntimeID: id, Dimension: dimension})
	}
	if t.containerOpen {
		packets = append(packets, &packet.ContainerClose{
			WindowID:      t.containerWindowID,
			ContainerType: t.containerType,
			ServerSide:    true,
		})
	}
	packets = append(packets,
		&packet.SetTitle{ActionType: packet.TitleActionClear},
		&packet.SetTitle{ActionType: packet.TitleActionReset},
		// A form left open could collide with a form ID the replacement opens.
		&packet.ClientBoundCloseForm{},
		emptyInventory(protocol.WindowIDInventory, protocol.ContainerCombinedHotBarAndInventory, 36),
		emptyInventory(protocol.WindowIDArmour, protocol.ContainerArmor, 4),
		emptyInventory(protocol.WindowIDOffHand, protocol.ContainerOffhand, 1),
	)
	selfListID := t.players[t.selfUUID]
	t.objectives = make(map[string]struct{})
	t.actors = make(map[int64]struct{})
	t.players = make(map[uuid.UUID]int64)
	if t.selfUUID != uuid.Nil {
		t.players[t.selfUUID] = selfListID
	}
	t.bossBars = make(map[int64]struct{})
	t.effects = make(map[int32]struct{})
	t.volumes = make(map[uint32]int32)
	t.containerOpen = false
	return packets
}

func emptyInventory(windowID uint32, containerID byte, slots int) packet.Packet {
	return &packet.InventoryContent{
		WindowID:  windowID,
		Content:   make([]protocol.ItemInstance, slots),
		Container: protocol.FullContainerName{ContainerID: containerID},
	}
}
