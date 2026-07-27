package packet

import (
	"sync/atomic"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// EntityIdentityTranslator swaps a retained local player identity with the identity assigned by the current server.
// It may be used when replacing a server connection while retaining the client connection.
type EntityIdentityTranslator struct {
	retained entityIdentity
	current  atomic.Pointer[entityIdentity]
}

type entityIdentity struct {
	runtimeID uint64
	uniqueID  int64
}

type entityIdentityMapping struct {
	retained entityIdentity
	current  entityIdentity
}

func (m entityIdentityMapping) runtimeID(id uint64) uint64 {
	switch id {
	case m.retained.runtimeID:
		return m.current.runtimeID
	case m.current.runtimeID:
		return m.retained.runtimeID
	default:
		return id
	}
}

func (m entityIdentityMapping) uniqueID(id int64) int64 {
	switch id {
	case m.retained.uniqueID:
		return m.current.uniqueID
	case m.current.uniqueID:
		return m.retained.uniqueID
	default:
		return id
	}
}

func (m entityIdentityMapping) entityLink(link protocol.EntityLink) protocol.EntityLink {
	link.RiddenEntityUniqueID = m.uniqueID(link.RiddenEntityUniqueID)
	link.RiderEntityUniqueID = m.uniqueID(link.RiderEntityUniqueID)
	return link
}

func (m entityIdentityMapping) metadata(values map[uint32]any) {
	for _, key := range []uint32{
		protocol.EntityDataKeyOwner,
		protocol.EntityDataKeyTarget,
		protocol.EntityDataKeyLeashHolder,
		protocol.EntityDataKeyTargetA,
		protocol.EntityDataKeyTargetB,
		protocol.EntityDataKeyTargetC,
		protocol.EntityDataKeyTradeTarget,
		protocol.EntityDataKeyBalloonAnchor,
		protocol.EntityDataKeyAgent,
		protocol.EntityDataKeyArrowShooterID,
		protocol.EntityDataKeyFireworkShooterID,
	} {
		switch id := values[key].(type) {
		case int64:
			values[key] = m.uniqueID(id)
		case uint64:
			values[key] = uint64(m.uniqueID(int64(id)))
		}
	}
	switch id := values[protocol.EntityDataKeyBaseRuntimeID].(type) {
	case int64:
		values[protocol.EntityDataKeyBaseRuntimeID] = int64(m.runtimeID(uint64(id)))
	case uint64:
		values[protocol.EntityDataKeyBaseRuntimeID] = m.runtimeID(id)
	}
}

// NewEntityIdentityTranslator creates an EntityIdentityTranslator with a retained local player identity. Until
// SetCurrent is called, Translate leaves this identity unchanged.
func NewEntityIdentityTranslator(runtimeID uint64, uniqueID int64) *EntityIdentityTranslator {
	t := &EntityIdentityTranslator{
		retained: entityIdentity{runtimeID: runtimeID, uniqueID: uniqueID},
	}
	t.SetCurrent(runtimeID, uniqueID)
	return t
}

// SetCurrent updates the local player identity assigned by the current server.
func (t *EntityIdentityTranslator) SetCurrent(runtimeID uint64, uniqueID int64) {
	t.current.Store(&entityIdentity{runtimeID: runtimeID, uniqueID: uniqueID})
}

// Translate swaps occurrences of the retained and current local player identities in pk. Calling Translate twice
// with no intervening SetCurrent call restores the packet to its original state.
func (t *EntityIdentityTranslator) Translate(pk Packet) {
	current := t.current.Load()
	if current == nil {
		return
	}
	mapping := entityIdentityMapping{retained: t.retained, current: *current}

	switch pk := pk.(type) {
	case *ActorEvent:
		pk.EntityRuntimeID = mapping.runtimeID(pk.EntityRuntimeID)
	case *ActorPickRequest:
		pk.EntityUniqueID = mapping.uniqueID(pk.EntityUniqueID)
	case *AgentAnimation:
		pk.EntityRuntimeID = mapping.runtimeID(pk.EntityRuntimeID)
	case *AddActor:
		pk.EntityUniqueID = mapping.uniqueID(pk.EntityUniqueID)
		pk.EntityRuntimeID = mapping.runtimeID(pk.EntityRuntimeID)
		mapping.metadata(pk.EntityMetadata)
		for i := range pk.EntityLinks {
			pk.EntityLinks[i] = mapping.entityLink(pk.EntityLinks[i])
		}
	case *AddItemActor:
		pk.EntityUniqueID = mapping.uniqueID(pk.EntityUniqueID)
		pk.EntityRuntimeID = mapping.runtimeID(pk.EntityRuntimeID)
		mapping.metadata(pk.EntityMetadata)
	case *AddPainting:
		pk.EntityUniqueID = mapping.uniqueID(pk.EntityUniqueID)
		pk.EntityRuntimeID = mapping.runtimeID(pk.EntityRuntimeID)
	case *AddPlayer:
		pk.AbilityData.EntityUniqueID = mapping.uniqueID(pk.AbilityData.EntityUniqueID)
		pk.EntityRuntimeID = mapping.runtimeID(pk.EntityRuntimeID)
		mapping.metadata(pk.EntityMetadata)
		for i := range pk.EntityLinks {
			pk.EntityLinks[i] = mapping.entityLink(pk.EntityLinks[i])
		}
	case *AddVolumeEntity:
		pk.EntityRuntimeID = uint32(mapping.runtimeID(uint64(pk.EntityRuntimeID)))
	case *AdventureSettings:
		pk.PlayerUniqueID = mapping.uniqueID(pk.PlayerUniqueID)
	case *Animate:
		pk.EntityRuntimeID = mapping.runtimeID(pk.EntityRuntimeID)
	case *AnimateEntity:
		for i := range pk.EntityRuntimeIDs {
			pk.EntityRuntimeIDs[i] = mapping.runtimeID(pk.EntityRuntimeIDs[i])
		}
	case *BossEvent:
		pk.BossEntityUniqueID = mapping.uniqueID(pk.BossEntityUniqueID)
		pk.PlayerUniqueID = mapping.uniqueID(pk.PlayerUniqueID)
	case *Camera:
		pk.CameraEntityUniqueID = mapping.uniqueID(pk.CameraEntityUniqueID)
		pk.TargetPlayerUniqueID = mapping.uniqueID(pk.TargetPlayerUniqueID)
	case *CameraInstruction:
		if target, ok := pk.Target.Value(); ok {
			target.EntityUniqueID = mapping.uniqueID(target.EntityUniqueID)
			pk.Target = protocol.Option(target)
		}
		if attached, ok := pk.AttachToEntity.Value(); ok {
			pk.AttachToEntity = protocol.Option(mapping.uniqueID(attached))
		}
	case *ChangeMobProperty:
		pk.EntityUniqueID = mapping.uniqueID(pk.EntityUniqueID)
	case *ClientBoundMapItemData:
		for i := range pk.TrackedObjects {
			if pk.TrackedObjects[i].Type == protocol.MapObjectTypeEntity {
				pk.TrackedObjects[i].EntityUniqueID = mapping.uniqueID(pk.TrackedObjects[i].EntityUniqueID)
			}
		}
	case *ClientCheatAbility:
		pk.AbilityData.EntityUniqueID = mapping.uniqueID(pk.AbilityData.EntityUniqueID)
	case *ClientMovementPredictionSync:
		pk.EntityUniqueID = mapping.uniqueID(pk.EntityUniqueID)
	case *CommandBlockUpdate:
		if !pk.Block {
			pk.MinecartEntityRuntimeID = mapping.runtimeID(pk.MinecartEntityRuntimeID)
		}
	case *CommandOutput:
		pk.CommandOrigin.PlayerUniqueID = mapping.uniqueID(pk.CommandOrigin.PlayerUniqueID)
	case *CommandRequest:
		pk.CommandOrigin.PlayerUniqueID = mapping.uniqueID(pk.CommandOrigin.PlayerUniqueID)
	case *ContainerOpen:
		pk.ContainerEntityUniqueID = mapping.uniqueID(pk.ContainerEntityUniqueID)
	case *CreatePhoto:
		pk.EntityUniqueID = mapping.uniqueID(pk.EntityUniqueID)
	case *DebugInfo:
		pk.PlayerUniqueID = mapping.uniqueID(pk.PlayerUniqueID)
	case *Emote:
		pk.EntityRuntimeID = mapping.runtimeID(pk.EntityRuntimeID)
	case *EmoteList:
		pk.PlayerRuntimeID = mapping.runtimeID(pk.PlayerRuntimeID)
	case *Event:
		pk.EntityRuntimeID = int64(mapping.runtimeID(uint64(pk.EntityRuntimeID)))
		switch event := pk.Event.(type) {
		case *protocol.EntityInteractEvent:
			event.InteractedEntityID = mapping.uniqueID(event.InteractedEntityID)
		case *protocol.MobKilledEvent:
			event.KillerEntityUniqueID = mapping.uniqueID(event.KillerEntityUniqueID)
			event.VictimEntityUniqueID = mapping.uniqueID(event.VictimEntityUniqueID)
		case *protocol.BossKilledEvent:
			event.BossEntityUniqueID = mapping.uniqueID(event.BossEntityUniqueID)
		}
	case *Interact:
		pk.TargetEntityRuntimeID = mapping.runtimeID(pk.TargetEntityRuntimeID)
	case *InventoryTransaction:
		if data, ok := pk.TransactionData.(*protocol.UseItemOnEntityTransactionData); ok {
			data.TargetEntityRuntimeID = mapping.runtimeID(data.TargetEntityRuntimeID)
		}
	case *LevelSoundEvent:
		pk.EntityUniqueID = mapping.uniqueID(pk.EntityUniqueID)
	case *LocatorBar:
		for i := range pk.Waypoints {
			if id, ok := pk.Waypoints[i].Waypoint.ActorUniqueID.Value(); ok {
				pk.Waypoints[i].Waypoint.ActorUniqueID = protocol.Option(mapping.uniqueID(id))
			}
		}
	case *MobArmourEquipment:
		pk.EntityRuntimeID = mapping.runtimeID(pk.EntityRuntimeID)
	case *MobEffect:
		pk.EntityRuntimeID = mapping.runtimeID(pk.EntityRuntimeID)
	case *MobEquipment:
		pk.EntityRuntimeID = mapping.runtimeID(pk.EntityRuntimeID)
	case *MotionPredictionHints:
		pk.EntityRuntimeID = mapping.runtimeID(pk.EntityRuntimeID)
	case *MovementEffect:
		pk.EntityRuntimeID = mapping.runtimeID(pk.EntityRuntimeID)
	case *MoveActorAbsolute:
		pk.EntityRuntimeID = mapping.runtimeID(pk.EntityRuntimeID)
	case *MoveActorDelta:
		pk.EntityRuntimeID = mapping.runtimeID(pk.EntityRuntimeID)
	case *MovePlayer:
		pk.EntityRuntimeID = mapping.runtimeID(pk.EntityRuntimeID)
		pk.RiddenEntityRuntimeID = mapping.runtimeID(pk.RiddenEntityRuntimeID)
	case *NPCDialogue:
		pk.EntityUniqueID = uint64(mapping.uniqueID(int64(pk.EntityUniqueID)))
	case *NPCRequest:
		pk.EntityRuntimeID = mapping.runtimeID(pk.EntityRuntimeID)
	case *PhotoTransfer:
		pk.OwnerEntityUniqueID = mapping.uniqueID(pk.OwnerEntityUniqueID)
	case *PlayerAction:
		pk.EntityRuntimeID = mapping.runtimeID(pk.EntityRuntimeID)
	case *PlayerAuthInput:
		if pk.InputData.Load(InputFlagClientPredictedVehicle) {
			pk.ClientPredictedVehicle = mapping.uniqueID(pk.ClientPredictedVehicle)
		}
	case *PlayerLocation:
		pk.EntityUniqueID = mapping.uniqueID(pk.EntityUniqueID)
	case *PlayerList:
		for i := range pk.Entries {
			pk.Entries[i].EntityUniqueID = mapping.uniqueID(pk.Entries[i].EntityUniqueID)
		}
	case *PlayerUpdateEntityOverrides:
		pk.EntityUniqueID = mapping.uniqueID(pk.EntityUniqueID)
	case *PrimitiveShapes:
		for i := range pk.Shapes {
			if id, ok := pk.Shapes[i].AttachedToEntityID.Value(); ok {
				pk.Shapes[i].AttachedToEntityID = protocol.Option(mapping.uniqueID(id))
			}
		}
	case *RemoveActor:
		pk.EntityUniqueID = mapping.uniqueID(pk.EntityUniqueID)
	case *RemoveVolumeEntity:
		pk.EntityRuntimeID = uint32(mapping.runtimeID(uint64(pk.EntityRuntimeID)))
	case *Respawn:
		pk.EntityRuntimeID = mapping.runtimeID(pk.EntityRuntimeID)
	case *RequestPermissions:
		pk.EntityUniqueID = mapping.uniqueID(pk.EntityUniqueID)
	case *SetActorData:
		pk.EntityRuntimeID = mapping.runtimeID(pk.EntityRuntimeID)
		mapping.metadata(pk.EntityMetadata)
	case *SetActorLink:
		pk.EntityLink = mapping.entityLink(pk.EntityLink)
	case *SetActorMotion:
		pk.EntityRuntimeID = mapping.runtimeID(pk.EntityRuntimeID)
	case *SetLocalPlayerAsInitialised:
		pk.EntityRuntimeID = mapping.runtimeID(pk.EntityRuntimeID)
	case *SetScore:
		for i := range pk.Entries {
			if pk.Entries[i].IdentityType != protocol.ScoreboardIdentityFakePlayer {
				pk.Entries[i].EntityUniqueID = mapping.uniqueID(pk.Entries[i].EntityUniqueID)
			}
		}
	case *SetScoreboardIdentity:
		if pk.ActionType != ScoreboardIdentityActionClear {
			for i := range pk.Entries {
				pk.Entries[i].EntityUniqueID = mapping.uniqueID(pk.Entries[i].EntityUniqueID)
			}
		}
	case *ShowCredits:
		pk.PlayerRuntimeID = mapping.runtimeID(pk.PlayerRuntimeID)
	case *SpawnParticleEffect:
		pk.EntityUniqueID = mapping.uniqueID(pk.EntityUniqueID)
	case *StartGame:
		pk.EntityUniqueID = mapping.uniqueID(pk.EntityUniqueID)
		pk.EntityRuntimeID = mapping.runtimeID(pk.EntityRuntimeID)
	case *StructureBlockUpdate:
		pk.Settings.LastEditingPlayerUniqueID = mapping.uniqueID(pk.Settings.LastEditingPlayerUniqueID)
	case *StructureTemplateDataRequest:
		pk.Settings.LastEditingPlayerUniqueID = mapping.uniqueID(pk.Settings.LastEditingPlayerUniqueID)
	case *TakeItemActor:
		pk.ItemEntityRuntimeID = mapping.runtimeID(pk.ItemEntityRuntimeID)
		pk.TakerEntityRuntimeID = mapping.runtimeID(pk.TakerEntityRuntimeID)
	case *UpdateAbilities:
		pk.AbilityData.EntityUniqueID = mapping.uniqueID(pk.AbilityData.EntityUniqueID)
	case *UpdateAttributes:
		pk.EntityRuntimeID = mapping.runtimeID(pk.EntityRuntimeID)
	case *UpdateBlockSynced:
		pk.EntityUniqueID = uint64(mapping.uniqueID(int64(pk.EntityUniqueID)))
	case *UpdateEquip:
		pk.EntityUniqueID = mapping.uniqueID(pk.EntityUniqueID)
	case *UpdatePlayerGameType:
		pk.PlayerUniqueID = mapping.uniqueID(pk.PlayerUniqueID)
	case *UpdateSubChunkBlocks:
		for i := range pk.Blocks {
			pk.Blocks[i].SyncedUpdateEntityUniqueID =
				uint64(mapping.uniqueID(int64(pk.Blocks[i].SyncedUpdateEntityUniqueID)))
		}
		for i := range pk.Extra {
			pk.Extra[i].SyncedUpdateEntityUniqueID =
				uint64(mapping.uniqueID(int64(pk.Extra[i].SyncedUpdateEntityUniqueID)))
		}
	case *UpdateTrade:
		pk.VillagerUniqueID = mapping.uniqueID(pk.VillagerUniqueID)
		pk.EntityUniqueID = mapping.uniqueID(pk.EntityUniqueID)
	}
}
