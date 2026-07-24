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

	runtimeID := func(id uint64) uint64 {
		switch id {
		case t.retained.runtimeID:
			return current.runtimeID
		case current.runtimeID:
			return t.retained.runtimeID
		default:
			return id
		}
	}
	uniqueID := func(id int64) int64 {
		switch id {
		case t.retained.uniqueID:
			return current.uniqueID
		case current.uniqueID:
			return t.retained.uniqueID
		default:
			return id
		}
	}
	entityLink := func(link protocol.EntityLink) protocol.EntityLink {
		link.RiddenEntityUniqueID = uniqueID(link.RiddenEntityUniqueID)
		link.RiderEntityUniqueID = uniqueID(link.RiderEntityUniqueID)
		return link
	}
	metadata := func(values map[uint32]any) {
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
				values[key] = uniqueID(id)
			case uint64:
				values[key] = uint64(uniqueID(int64(id)))
			}
		}
		switch id := values[protocol.EntityDataKeyBaseRuntimeID].(type) {
		case int64:
			values[protocol.EntityDataKeyBaseRuntimeID] = int64(runtimeID(uint64(id)))
		case uint64:
			values[protocol.EntityDataKeyBaseRuntimeID] = runtimeID(id)
		}
	}

	switch pk := pk.(type) {
	case *ActorEvent:
		pk.EntityRuntimeID = runtimeID(pk.EntityRuntimeID)
	case *ActorPickRequest:
		pk.EntityUniqueID = uniqueID(pk.EntityUniqueID)
	case *AgentAnimation:
		pk.EntityRuntimeID = runtimeID(pk.EntityRuntimeID)
	case *AddActor:
		pk.EntityUniqueID = uniqueID(pk.EntityUniqueID)
		pk.EntityRuntimeID = runtimeID(pk.EntityRuntimeID)
		metadata(pk.EntityMetadata)
		for i := range pk.EntityLinks {
			pk.EntityLinks[i] = entityLink(pk.EntityLinks[i])
		}
	case *AddItemActor:
		pk.EntityUniqueID = uniqueID(pk.EntityUniqueID)
		pk.EntityRuntimeID = runtimeID(pk.EntityRuntimeID)
		metadata(pk.EntityMetadata)
	case *AddPainting:
		pk.EntityUniqueID = uniqueID(pk.EntityUniqueID)
		pk.EntityRuntimeID = runtimeID(pk.EntityRuntimeID)
	case *AddPlayer:
		pk.AbilityData.EntityUniqueID = uniqueID(pk.AbilityData.EntityUniqueID)
		pk.EntityRuntimeID = runtimeID(pk.EntityRuntimeID)
		metadata(pk.EntityMetadata)
		for i := range pk.EntityLinks {
			pk.EntityLinks[i] = entityLink(pk.EntityLinks[i])
		}
	case *AddVolumeEntity:
		pk.EntityRuntimeID = uint32(runtimeID(uint64(pk.EntityRuntimeID)))
	case *AdventureSettings:
		pk.PlayerUniqueID = uniqueID(pk.PlayerUniqueID)
	case *Animate:
		pk.EntityRuntimeID = runtimeID(pk.EntityRuntimeID)
	case *AnimateEntity:
		for i := range pk.EntityRuntimeIDs {
			pk.EntityRuntimeIDs[i] = runtimeID(pk.EntityRuntimeIDs[i])
		}
	case *BossEvent:
		pk.BossEntityUniqueID = uniqueID(pk.BossEntityUniqueID)
		pk.PlayerUniqueID = uniqueID(pk.PlayerUniqueID)
	case *Camera:
		pk.CameraEntityUniqueID = uniqueID(pk.CameraEntityUniqueID)
		pk.TargetPlayerUniqueID = uniqueID(pk.TargetPlayerUniqueID)
	case *CameraInstruction:
		if target, ok := pk.Target.Value(); ok {
			target.EntityUniqueID = uniqueID(target.EntityUniqueID)
			pk.Target = protocol.Option(target)
		}
		if attached, ok := pk.AttachToEntity.Value(); ok {
			pk.AttachToEntity = protocol.Option(uniqueID(attached))
		}
	case *ChangeMobProperty:
		pk.EntityUniqueID = uniqueID(pk.EntityUniqueID)
	case *ClientBoundMapItemData:
		for i := range pk.TrackedObjects {
			if pk.TrackedObjects[i].Type == protocol.MapObjectTypeEntity {
				pk.TrackedObjects[i].EntityUniqueID = uniqueID(pk.TrackedObjects[i].EntityUniqueID)
			}
		}
	case *ClientCheatAbility:
		pk.AbilityData.EntityUniqueID = uniqueID(pk.AbilityData.EntityUniqueID)
	case *ClientMovementPredictionSync:
		pk.EntityUniqueID = uniqueID(pk.EntityUniqueID)
	case *CommandBlockUpdate:
		if !pk.Block {
			pk.MinecartEntityRuntimeID = runtimeID(pk.MinecartEntityRuntimeID)
		}
	case *CommandOutput:
		pk.CommandOrigin.PlayerUniqueID = uniqueID(pk.CommandOrigin.PlayerUniqueID)
	case *CommandRequest:
		pk.CommandOrigin.PlayerUniqueID = uniqueID(pk.CommandOrigin.PlayerUniqueID)
	case *ContainerOpen:
		pk.ContainerEntityUniqueID = uniqueID(pk.ContainerEntityUniqueID)
	case *CreatePhoto:
		pk.EntityUniqueID = uniqueID(pk.EntityUniqueID)
	case *DebugInfo:
		pk.PlayerUniqueID = uniqueID(pk.PlayerUniqueID)
	case *Emote:
		pk.EntityRuntimeID = runtimeID(pk.EntityRuntimeID)
	case *EmoteList:
		pk.PlayerRuntimeID = runtimeID(pk.PlayerRuntimeID)
	case *Event:
		pk.EntityRuntimeID = int64(runtimeID(uint64(pk.EntityRuntimeID)))
		switch event := pk.Event.(type) {
		case *protocol.EntityInteractEvent:
			event.InteractedEntityID = uniqueID(event.InteractedEntityID)
		case *protocol.MobKilledEvent:
			event.KillerEntityUniqueID = uniqueID(event.KillerEntityUniqueID)
			event.VictimEntityUniqueID = uniqueID(event.VictimEntityUniqueID)
		case *protocol.BossKilledEvent:
			event.BossEntityUniqueID = uniqueID(event.BossEntityUniqueID)
		}
	case *Interact:
		pk.TargetEntityRuntimeID = runtimeID(pk.TargetEntityRuntimeID)
	case *InventoryTransaction:
		if data, ok := pk.TransactionData.(*protocol.UseItemOnEntityTransactionData); ok {
			data.TargetEntityRuntimeID = runtimeID(data.TargetEntityRuntimeID)
		}
	case *LevelSoundEvent:
		pk.EntityUniqueID = uniqueID(pk.EntityUniqueID)
	case *LocatorBar:
		for i := range pk.Waypoints {
			if id, ok := pk.Waypoints[i].Waypoint.ActorUniqueID.Value(); ok {
				pk.Waypoints[i].Waypoint.ActorUniqueID = protocol.Option(uniqueID(id))
			}
		}
	case *MobArmourEquipment:
		pk.EntityRuntimeID = runtimeID(pk.EntityRuntimeID)
	case *MobEffect:
		pk.EntityRuntimeID = runtimeID(pk.EntityRuntimeID)
	case *MobEquipment:
		pk.EntityRuntimeID = runtimeID(pk.EntityRuntimeID)
	case *MotionPredictionHints:
		pk.EntityRuntimeID = runtimeID(pk.EntityRuntimeID)
	case *MovementEffect:
		pk.EntityRuntimeID = runtimeID(pk.EntityRuntimeID)
	case *MoveActorAbsolute:
		pk.EntityRuntimeID = runtimeID(pk.EntityRuntimeID)
	case *MoveActorDelta:
		pk.EntityRuntimeID = runtimeID(pk.EntityRuntimeID)
	case *MovePlayer:
		pk.EntityRuntimeID = runtimeID(pk.EntityRuntimeID)
		pk.RiddenEntityRuntimeID = runtimeID(pk.RiddenEntityRuntimeID)
	case *NPCDialogue:
		pk.EntityUniqueID = uint64(uniqueID(int64(pk.EntityUniqueID)))
	case *NPCRequest:
		pk.EntityRuntimeID = runtimeID(pk.EntityRuntimeID)
	case *PhotoTransfer:
		pk.OwnerEntityUniqueID = uniqueID(pk.OwnerEntityUniqueID)
	case *PlayerAction:
		pk.EntityRuntimeID = runtimeID(pk.EntityRuntimeID)
	case *PlayerAuthInput:
		if pk.InputData.Load(InputFlagClientPredictedVehicle) {
			pk.ClientPredictedVehicle = uniqueID(pk.ClientPredictedVehicle)
		}
	case *PlayerLocation:
		pk.EntityUniqueID = uniqueID(pk.EntityUniqueID)
	case *PlayerList:
		for i := range pk.Entries {
			pk.Entries[i].EntityUniqueID = uniqueID(pk.Entries[i].EntityUniqueID)
		}
	case *PlayerUpdateEntityOverrides:
		pk.EntityUniqueID = uniqueID(pk.EntityUniqueID)
	case *PrimitiveShapes:
		for i := range pk.Shapes {
			if id, ok := pk.Shapes[i].AttachedToEntityID.Value(); ok {
				pk.Shapes[i].AttachedToEntityID = protocol.Option(uniqueID(id))
			}
		}
	case *RemoveActor:
		pk.EntityUniqueID = uniqueID(pk.EntityUniqueID)
	case *RemoveVolumeEntity:
		pk.EntityRuntimeID = uint32(runtimeID(uint64(pk.EntityRuntimeID)))
	case *Respawn:
		pk.EntityRuntimeID = runtimeID(pk.EntityRuntimeID)
	case *RequestPermissions:
		pk.EntityUniqueID = uniqueID(pk.EntityUniqueID)
	case *SetActorData:
		pk.EntityRuntimeID = runtimeID(pk.EntityRuntimeID)
		metadata(pk.EntityMetadata)
	case *SetActorLink:
		pk.EntityLink = entityLink(pk.EntityLink)
	case *SetActorMotion:
		pk.EntityRuntimeID = runtimeID(pk.EntityRuntimeID)
	case *SetLocalPlayerAsInitialised:
		pk.EntityRuntimeID = runtimeID(pk.EntityRuntimeID)
	case *SetScore:
		for i := range pk.Entries {
			if pk.Entries[i].IdentityType != protocol.ScoreboardIdentityFakePlayer {
				pk.Entries[i].EntityUniqueID = uniqueID(pk.Entries[i].EntityUniqueID)
			}
		}
	case *SetScoreboardIdentity:
		if pk.ActionType != ScoreboardIdentityActionClear {
			for i := range pk.Entries {
				pk.Entries[i].EntityUniqueID = uniqueID(pk.Entries[i].EntityUniqueID)
			}
		}
	case *ShowCredits:
		pk.PlayerRuntimeID = runtimeID(pk.PlayerRuntimeID)
	case *SpawnParticleEffect:
		pk.EntityUniqueID = uniqueID(pk.EntityUniqueID)
	case *StartGame:
		pk.EntityUniqueID = uniqueID(pk.EntityUniqueID)
		pk.EntityRuntimeID = runtimeID(pk.EntityRuntimeID)
	case *StructureBlockUpdate:
		pk.Settings.LastEditingPlayerUniqueID = uniqueID(pk.Settings.LastEditingPlayerUniqueID)
	case *StructureTemplateDataRequest:
		pk.Settings.LastEditingPlayerUniqueID = uniqueID(pk.Settings.LastEditingPlayerUniqueID)
	case *TakeItemActor:
		pk.ItemEntityRuntimeID = runtimeID(pk.ItemEntityRuntimeID)
		pk.TakerEntityRuntimeID = runtimeID(pk.TakerEntityRuntimeID)
	case *UpdateAbilities:
		pk.AbilityData.EntityUniqueID = uniqueID(pk.AbilityData.EntityUniqueID)
	case *UpdateAttributes:
		pk.EntityRuntimeID = runtimeID(pk.EntityRuntimeID)
	case *UpdateBlockSynced:
		pk.EntityUniqueID = uint64(uniqueID(int64(pk.EntityUniqueID)))
	case *UpdateEquip:
		pk.EntityUniqueID = uniqueID(pk.EntityUniqueID)
	case *UpdatePlayerGameType:
		pk.PlayerUniqueID = uniqueID(pk.PlayerUniqueID)
	case *UpdateSubChunkBlocks:
		for i := range pk.Blocks {
			pk.Blocks[i].SyncedUpdateEntityUniqueID =
				uint64(uniqueID(int64(pk.Blocks[i].SyncedUpdateEntityUniqueID)))
		}
		for i := range pk.Extra {
			pk.Extra[i].SyncedUpdateEntityUniqueID =
				uint64(uniqueID(int64(pk.Extra[i].SyncedUpdateEntityUniqueID)))
		}
	case *UpdateTrade:
		pk.VillagerUniqueID = uniqueID(pk.VillagerUniqueID)
		pk.EntityUniqueID = uniqueID(pk.EntityUniqueID)
	}
}
