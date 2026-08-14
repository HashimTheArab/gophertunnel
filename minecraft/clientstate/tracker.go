// Package clientstate tracks the client-visible state a server builds up on a
// Bedrock connection, so a proxy replacing that server can take the state back
// off the client without reconnecting it.
package clientstate

import (
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// Self identifies the connection's own player entity, so state on other
// entities and the player's own list entry can be told apart. A zero Self
// disables self recognition for the call it is passed to.
type Self struct {
	RuntimeID uint64
	UniqueID  int64
}

// Tracker mirrors the client-visible state built up by packets delivered to a
// client: entities, player-list entries, boss bars, own-player effects,
// scoreboard objectives, volume entities and the open container. It is not safe
// for concurrent use; the caller synchronizes Observe against ClearPackets.
type Tracker struct {
	// objectives holds every objective the client still has registered. A server
	// may point a display slot at a new objective without removing the old one,
	// and the client keeps the old one until it is explicitly removed.
	objectives map[string]struct{}
	actors     map[int64]struct{}
	// players maps each list entry to its entity unique ID, so an AddPlayer
	// whose ability data carries no unique ID can still be recorded under the
	// ID a later RemoveActor identifies it by.
	players           map[uuid.UUID]int64
	bossBars          map[int64]struct{}
	effects           map[int32]struct{}
	volumes           map[uint32]int32
	containerOpen     bool
	containerWindowID byte
	containerType     byte
	// selfUUID is the UUID of the player's own list entry, recognized by unique
	// ID. It survives ClearPackets: the entry is retained on the client.
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

// Observe records the state pk creates or removes. Only packets actually
// delivered to the client may be observed: ClearPackets must target the state
// the client really holds, not what the server tried to send.
func (t *Tracker) Observe(pk packet.Packet, self Self) {
	switch pk := pk.(type) {
	case *packet.SetDisplayObjective:
		// The objective a slot stops showing stays registered on the client, so
		// it is only dropped by an explicit RemoveObjective.
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
		// Ability data may carry no unique ID; the list entry that preceded the
		// AddPlayer knows it, and only then does the runtime ID stand in.
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

// ObserveClient records client-authored state changes, currently a client
// closing the open container on its own.
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

// ClearPackets returns packets that take every piece of tracked state off the
// client, plus the state no packet announces: titles, an open form and the
// inventory. The player's own entity and list entry are retained. The Tracker
// resets to track the next server's state.
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
		// Drop any form the retired server left open, so the client cannot
		// submit its ID to the replacement and collide with a form the
		// replacement opens later.
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
