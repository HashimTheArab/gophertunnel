package packet

import (
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// idFieldPattern matches struct field names that suggest the field carries an entity
// runtime or unique ID. Fields named after their meaning rather than their ID kind are
// listed explicitly.
var idFieldPattern = regexp.MustCompile(`RuntimeID|UniqueID|ActorID|EntityID|ClientPredictedVehicle|AttachToEntity`)

// tickFieldPattern matches a bare Tick or an InputTick suffix; duration-style fields
// (TickDelay, TransitionTicks, ...) do not match, and neither does the legacy shield
// ItemStack.BlockingTick, a level tick serialized in the item's nested data buffer.
var tickFieldPattern = regexp.MustCompile(`(^|Input)Tick$`)

// translatedIDFields lists every entity ID field, as a path from the packet struct, that
// TranslateEntityIDs rewrites and that idFieldPattern can discover. IDs behind interface
// fields and entity metadata map values are translated but not discoverable.
var translatedIDFields = []string{
	"ActorEvent.EntityRuntimeID",
	"ActorPickRequest.EntityUniqueID",
	"AddActor.EntityLinks[].RiddenEntityUniqueID",
	"AddActor.EntityLinks[].RiderEntityUniqueID",
	"AddActor.EntityRuntimeID",
	"AddActor.EntityUniqueID",
	"AddItemActor.EntityRuntimeID",
	"AddItemActor.EntityUniqueID",
	"AddPainting.EntityRuntimeID",
	"AddPainting.EntityUniqueID",
	"AddPlayer.AbilityData.EntityUniqueID",
	"AddPlayer.EntityLinks[].RiddenEntityUniqueID",
	"AddPlayer.EntityLinks[].RiderEntityUniqueID",
	"AddPlayer.EntityRuntimeID",
	"AddVolumeEntity.EntityRuntimeID",
	"AdventureSettings.PlayerUniqueID",
	"AgentAnimation.EntityRuntimeID",
	"Animate.EntityRuntimeID",
	"AnimateEntity.EntityRuntimeIDs",
	"BossEvent.BossEntityUniqueID",
	"BossEvent.PlayerUniqueID",
	"Camera.CameraEntityUniqueID",
	"Camera.TargetPlayerUniqueID",
	"CameraInstruction.AttachToEntity",
	"CameraInstruction.Target.EntityUniqueID",
	"ChangeMobProperty.EntityUniqueID",
	"ClientBoundMapItemData.TrackedObjects[].EntityUniqueID",
	"ClientCheatAbility.AbilityData.EntityUniqueID",
	"ClientMovementPredictionSync.EntityUniqueID",
	"CommandBlockUpdate.MinecartEntityRuntimeID",
	"CommandOutput.CommandOrigin.PlayerUniqueID",
	"CommandRequest.CommandOrigin.PlayerUniqueID",
	"ContainerOpen.ContainerEntityUniqueID",
	"CreatePhoto.EntityUniqueID",
	"DebugInfo.PlayerUniqueID",
	"Emote.EntityRuntimeID",
	"EmoteList.PlayerRuntimeID",
	"Event.EntityRuntimeID",
	"Interact.TargetEntityRuntimeID",
	"LevelSoundEvent.EntityUniqueID",
	"LocatorBar.Waypoints[].Waypoint.ActorUniqueID",
	"MobArmourEquipment.EntityRuntimeID",
	"MobEffect.EntityRuntimeID",
	"MobEquipment.EntityRuntimeID",
	"MotionPredictionHints.EntityRuntimeID",
	"MoveActorAbsolute.EntityRuntimeID",
	"MoveActorDelta.EntityRuntimeID",
	"MovePlayer.EntityRuntimeID",
	"MovePlayer.RiddenEntityRuntimeID",
	"MovementEffect.EntityRuntimeID",
	"NPCDialogue.EntityUniqueID",
	"NPCRequest.EntityRuntimeID",
	"PhotoTransfer.OwnerEntityUniqueID",
	"PlayerAction.EntityRuntimeID",
	"PlayerAuthInput.ClientPredictedVehicle",
	"PlayerList.Entries[].EntityUniqueID",
	"PlayerLocation.EntityUniqueID",
	"PlayerUpdateEntityOverrides.EntityUniqueID",
	"PrimitiveShapes.Shapes[].AttachedToEntityID",
	"RemoveActor.EntityUniqueID",
	"RemoveVolumeEntity.EntityRuntimeID",
	"RequestPermissions.EntityUniqueID",
	"Respawn.EntityRuntimeID",
	"SetActorData.EntityRuntimeID",
	"SetActorLink.EntityLink.RiddenEntityUniqueID",
	"SetActorLink.EntityLink.RiderEntityUniqueID",
	"SetActorMotion.EntityRuntimeID",
	"SetLocalPlayerAsInitialised.EntityRuntimeID",
	"SetScore.Entries[].EntityUniqueID",
	"SetScoreboardIdentity.Entries[].EntityUniqueID",
	"ShowCredits.PlayerRuntimeID",
	"SpawnParticleEffect.EntityUniqueID",
	"StartGame.EntityRuntimeID",
	"StartGame.EntityUniqueID",
	"StructureBlockUpdate.Settings.LastEditingPlayerUniqueID",
	"StructureTemplateDataRequest.Settings.LastEditingPlayerUniqueID",
	"TakeItemActor.ItemEntityRuntimeID",
	"TakeItemActor.TakerEntityRuntimeID",
	"UpdateAbilities.AbilityData.EntityUniqueID",
	"UpdateAttributes.EntityRuntimeID",
	"UpdateBlockSynced.EntityUniqueID",
	"UpdateEquip.EntityUniqueID",
	"UpdatePlayerGameType.PlayerUniqueID",
	"UpdateSubChunkBlocks.Blocks[].SyncedUpdateEntityUniqueID",
	"UpdateSubChunkBlocks.Extra[].SyncedUpdateEntityUniqueID",
	"UpdateTrade.EntityUniqueID",
	"UpdateTrade.VillagerUniqueID",
}

// translatedTickFields lists every player input tick field, as a path from the packet
// struct, that TranslateInputTicks rewrites and that tickFieldPattern can discover.
var translatedTickFields = []string{
	"CorrectPlayerMovePrediction.Tick",
	"MobEffect.Tick",
	"MovePlayer.Tick",
	"MovementEffect.Tick",
	"PlayerAuthInput.Tick",
	"SetActorData.Tick",
	"SetActorMotion.Tick",
	"UpdateAttributes.Tick",
	"UpdatePlayerGameType.Tick",
}

// ignoredIDFields lists fields matched by the naming heuristic that TranslateEntityIDs
// deliberately leaves untouched, with the reason.
var ignoredIDFields = map[string]string{
	"ItemRegistry.Items[].RuntimeID": "item type network ID, not an entity ID",
}

// TestTranslateEntityIDsCoverage fails when a packet field that looks like an entity ID
// is neither translated nor deliberately ignored, so that a protocol update adding one
// breaks this test until TranslateEntityIDs is brought back in sync. Block runtime IDs
// are out of scope; interface implementations carrying entity IDs must be covered by
// hand.
func TestTranslateEntityIDsCoverage(t *testing.T) {
	discovered := map[string]bool{}
	seen := map[reflect.Type]bool{}
	for _, pool := range []Pool{NewClientPool(), NewServerPool()} {
		for _, newPk := range pool {
			typ := reflect.TypeOf(newPk()).Elem()
			if seen[typ] {
				continue
			}
			seen[typ] = true
			walkMatchingFields(typ, typ.Name(), discovered, map[reflect.Type]bool{}, isIDField)
		}
	}

	expected := map[string]bool{}
	for _, path := range translatedIDFields {
		expected[path] = true
	}
	for path := range ignoredIDFields {
		expected[path] = true
	}
	reportCoverage(t, "entity ID", "TranslateEntityIDs", discovered, expected)
}

// TestTranslateInputTicksCoverage fails when a packet field that looks like a player
// input tick is not translated, so a protocol update adding one breaks this test.
func TestTranslateInputTicksCoverage(t *testing.T) {
	discovered := map[string]bool{}
	seen := map[reflect.Type]bool{}
	for _, pool := range []Pool{NewClientPool(), NewServerPool()} {
		for _, newPk := range pool {
			typ := reflect.TypeOf(newPk()).Elem()
			if seen[typ] {
				continue
			}
			seen[typ] = true
			walkMatchingFields(typ, typ.Name(), discovered, map[reflect.Type]bool{}, tickFieldPattern.MatchString)
		}
	}

	expected := map[string]bool{}
	for _, path := range translatedTickFields {
		expected[path] = true
	}
	reportCoverage(t, "player input tick", "TranslateInputTicks", discovered, expected)
}

// reportCoverage diffs the field paths a discovery walk found against the paths a
// translation function covers, reporting both directions of drift.
func reportCoverage(t *testing.T, kind, translator string, discovered, expected map[string]bool) {
	t.Helper()
	var missing, stale []string
	for path := range discovered {
		if !expected[path] {
			missing = append(missing, path)
		}
	}
	for path := range expected {
		if !discovered[path] {
			stale = append(stale, path)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	for _, path := range missing {
		t.Errorf("%v field %v is neither translated by %v nor listed as ignored", kind, path, translator)
	}
	for _, path := range stale {
		t.Errorf("listed %v field %v no longer exists in the packet package", kind, path)
	}
}

// isIDField reports whether a struct field name suggests an entity ID, excluding block
// runtime IDs, which are not entity IDs.
func isIDField(name string) bool {
	return idFieldPattern.MatchString(name) && !strings.Contains(name, "BlockRuntimeID")
}

// walkMatchingFields recursively collects the paths of fields of a packet struct type
// whose names satisfy match, reporting fields of protocol.Optional types as the optional
// field itself.
func walkMatchingFields(typ reflect.Type, path string, found map[string]bool, visiting map[reflect.Type]bool, match func(string) bool) {
	switch typ.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		walkMatchingFields(typ.Elem(), path+"[]", found, visiting, match)
	case reflect.Map:
		walkMatchingFields(typ.Elem(), path+"{}", found, visiting, match)
	case reflect.Struct:
		if visiting[typ] {
			return
		}
		visiting[typ] = true
		defer delete(visiting, typ)
		optional := strings.HasPrefix(typ.Name(), "Optional[")
		for field := range typ.Fields() {
			fieldPath := path + "." + field.Name
			if optional {
				fieldPath = path
			}
			if !optional && match(field.Name) {
				found[fieldPath] = true
				continue
			}
			walkMatchingFields(field.Type, fieldPath, found, visiting, match)
		}
	}
}

// translateSwap swaps between the (10, 100) and (20, 200) (unique, runtime) identities.
func translateSwap(pk Packet) {
	rid := func(id uint64) uint64 {
		switch id {
		case 100:
			return 200
		case 200:
			return 100
		}
		return id
	}
	uid := func(id int64) int64 {
		switch id {
		case 10:
			return 20
		case 20:
			return 10
		}
		return id
	}
	TranslateEntityIDs(pk, rid, uid)
}

func TestTranslateEntityIDsSimpleFields(t *testing.T) {
	pk := &StartGame{EntityUniqueID: 10, EntityRuntimeID: 200}
	translateSwap(pk)
	if pk.EntityUniqueID != 20 || pk.EntityRuntimeID != 100 {
		t.Errorf("unexpected IDs after translation: unique %v, runtime %v", pk.EntityUniqueID, pk.EntityRuntimeID)
	}
	move := &MovePlayer{EntityRuntimeID: 100, RiddenEntityRuntimeID: 300}
	translateSwap(move)
	if move.EntityRuntimeID != 200 || move.RiddenEntityRuntimeID != 300 {
		t.Errorf("unexpected IDs after translation: runtime %v, ridden %v", move.EntityRuntimeID, move.RiddenEntityRuntimeID)
	}
}

func TestTranslateEntityIDsNilCallbacks(t *testing.T) {
	pk := &StartGame{EntityUniqueID: 10, EntityRuntimeID: 100}
	TranslateEntityIDs(pk, nil, nil)
	if pk.EntityUniqueID != 10 || pk.EntityRuntimeID != 100 {
		t.Errorf("nil callbacks changed IDs: unique %v, runtime %v", pk.EntityUniqueID, pk.EntityRuntimeID)
	}
}

func TestTranslateInputTicks(t *testing.T) {
	pk := &MovePlayer{EntityRuntimeID: 100, Tick: 5}
	TranslateInputTicks(pk, func(tick uint64) uint64 { return tick + 1000 })
	if pk.Tick != 1005 {
		t.Errorf("tick not translated: %v", pk.Tick)
	}
	if pk.EntityRuntimeID != 100 {
		t.Errorf("tick translation changed the runtime ID: %v", pk.EntityRuntimeID)
	}
	TranslateInputTicks(pk, nil)
	if pk.Tick != 1005 {
		t.Errorf("nil callback changed the tick: %v", pk.Tick)
	}
}

func TestTranslateEntityIDsMetadataAndLinks(t *testing.T) {
	pk := &AddActor{
		EntityUniqueID:  10,
		EntityRuntimeID: 100,
		EntityMetadata: map[uint32]any{
			protocol.EntityDataKeyOwner:                    int64(10),
			protocol.EntityDataKeyTarget:                   uint64(20),
			protocol.EntityDataKeyLeashHolder:              int64(30),
			protocol.EntityDataKeyAimAssistPriorityActorID: int64(20),
			protocol.EntityDataKeyName:                     "unrelated",
		},
		EntityLinks: []protocol.EntityLink{{RiddenEntityUniqueID: 20, RiderEntityUniqueID: 10}},
	}
	translateSwap(pk)
	if pk.EntityUniqueID != 20 || pk.EntityRuntimeID != 200 {
		t.Errorf("unexpected IDs after translation: unique %v, runtime %v", pk.EntityUniqueID, pk.EntityRuntimeID)
	}
	if owner := pk.EntityMetadata[protocol.EntityDataKeyOwner]; owner != int64(20) {
		t.Errorf("unexpected owner metadata after translation: %v", owner)
	}
	if target := pk.EntityMetadata[protocol.EntityDataKeyTarget]; target != uint64(10) {
		t.Errorf("unexpected target metadata after translation: %v", target)
	}
	if holder := pk.EntityMetadata[protocol.EntityDataKeyLeashHolder]; holder != int64(30) {
		t.Errorf("unexpected leash holder metadata after translation: %v", holder)
	}
	if aim := pk.EntityMetadata[protocol.EntityDataKeyAimAssistPriorityActorID]; aim != int64(10) {
		t.Errorf("unexpected aim assist actor metadata after translation: %v", aim)
	}
	if link := pk.EntityLinks[0]; link.RiddenEntityUniqueID != 10 || link.RiderEntityUniqueID != 20 {
		t.Errorf("unexpected entity link after translation: %+v", link)
	}
}

func TestTranslateEntityIDsConditionalFields(t *testing.T) {
	block := &CommandBlockUpdate{Block: true, MinecartEntityRuntimeID: 100}
	translateSwap(block)
	if block.MinecartEntityRuntimeID != 100 {
		t.Errorf("block-mode CommandBlockUpdate minecart ID translated to %v", block.MinecartEntityRuntimeID)
	}
	minecart := &CommandBlockUpdate{Block: false, MinecartEntityRuntimeID: 100}
	translateSwap(minecart)
	if minecart.MinecartEntityRuntimeID != 200 {
		t.Errorf("minecart CommandBlockUpdate ID not translated: %v", minecart.MinecartEntityRuntimeID)
	}

	input := &PlayerAuthInput{}
	translateSwap(input)
	if _, ok := input.ClientPredictedVehicle.Value(); ok {
		t.Error("absent predicted vehicle became present during translation")
	}
	input.ClientPredictedVehicle = protocol.Option[int64](10)
	translateSwap(input)
	if predictedVehicle, _ := input.ClientPredictedVehicle.Value(); predictedVehicle != 20 {
		t.Errorf("present predicted vehicle not translated: %v", predictedVehicle)
	}

	score := &SetScore{Entries: []protocol.ScoreboardEntry{
		{IdentityType: protocol.ScoreboardIdentityPlayer, EntityUniqueID: 10},
		{IdentityType: protocol.ScoreboardIdentityFakePlayer, EntityUniqueID: 10},
	}}
	translateSwap(score)
	if score.Entries[0].EntityUniqueID != 20 {
		t.Errorf("player scoreboard entry not translated: %v", score.Entries[0].EntityUniqueID)
	}
	if score.Entries[1].EntityUniqueID != 10 {
		t.Errorf("fake player scoreboard entry translated: %v", score.Entries[1].EntityUniqueID)
	}
}

func TestTranslateEntityIDsInterfaceFields(t *testing.T) {
	tx := &InventoryTransaction{TransactionData: &protocol.UseItemOnEntityTransactionData{TargetEntityRuntimeID: 100}}
	translateSwap(tx)
	if id := tx.TransactionData.(*protocol.UseItemOnEntityTransactionData).TargetEntityRuntimeID; id != 200 {
		t.Errorf("use item on entity target not translated: %v", id)
	}

	event := &Event{EntityRuntimeID: 100, Event: &protocol.MobKilledEvent{KillerEntityUniqueID: 10, VictimEntityUniqueID: 20}}
	translateSwap(event)
	if event.EntityRuntimeID != 200 {
		t.Errorf("event runtime ID not translated: %v", event.EntityRuntimeID)
	}
	killed := event.Event.(*protocol.MobKilledEvent)
	if killed.KillerEntityUniqueID != 20 || killed.VictimEntityUniqueID != 10 {
		t.Errorf("mob killed event not translated: %+v", killed)
	}

	interact := &Event{Event: &protocol.EntityInteractEvent{InteractedEntityID: 10}}
	translateSwap(interact)
	if id := interact.Event.(*protocol.EntityInteractEvent).InteractedEntityID; id != 20 {
		t.Errorf("entity interact event not translated: %v", id)
	}
}

func TestTranslateEntityIDsOptionalFields(t *testing.T) {
	camera := &CameraInstruction{
		Target:         protocol.Option(protocol.CameraInstructionTarget{EntityUniqueID: 10}),
		AttachToEntity: protocol.Option(int64(20)),
	}
	translateSwap(camera)
	if target, _ := camera.Target.Value(); target.EntityUniqueID != 20 {
		t.Errorf("camera target not translated: %v", target.EntityUniqueID)
	}
	if attached, _ := camera.AttachToEntity.Value(); attached != 10 {
		t.Errorf("camera attach entity not translated: %v", attached)
	}

	empty := &CameraInstruction{}
	translateSwap(empty)
	if _, ok := empty.Target.Value(); ok {
		t.Error("empty camera target became set")
	}
}

type marshalIDPacket struct {
	runtimeID uint64
	uniqueID  int64
}

func (*marshalIDPacket) ID() uint32 { return 0 }

func (pk *marshalIDPacket) Marshal(raw protocol.IO) {
	io := any(raw).(interface {
		ActorRuntimeID(*uint64)
		ActorUniqueID(*int64)
	})
	io.ActorRuntimeID(&pk.runtimeID)
	io.ActorUniqueID(&pk.uniqueID)
}

func TestTranslateEntityIDsUsesPacketMarshal(t *testing.T) {
	pk := &marshalIDPacket{runtimeID: 100, uniqueID: 10}
	translateSwap(pk)
	if pk.runtimeID != 200 || pk.uniqueID != 20 {
		t.Fatalf("packet Marshal IDs were not translated: runtime %v, unique %v", pk.runtimeID, pk.uniqueID)
	}
}

func TestTranslateEntityIDsLegacyAndNestedFields(t *testing.T) {
	shape := &PrimitiveShapes{Shapes: []protocol.PrimitiveShape{{
		AttachedToEntityID: protocol.Option(int64(100)),
		ExtraShapeData:     &protocol.LastShape{},
	}}}
	waypoint := &LocatorBar{Waypoints: []protocol.LocatorBarWaypoint{{
		Waypoint: protocol.Waypoint{ActorUniqueID: protocol.Option(int64(10))},
	}}}
	camera := &CameraInstruction{AttachToEntity: protocol.Option(int64(10))}

	// Keep the assertions close to each packet so a field's wire-specific helper cannot
	// silently stop participating in the marshal traversal.
	adventure := &AdventureSettings{PlayerUniqueID: 10}
	translateSwap(adventure)
	if adventure.PlayerUniqueID != 20 {
		t.Fatalf("adventure settings unique ID = %v, want 20", adventure.PlayerUniqueID)
	}

	sound := &LevelSoundEvent{EntityUniqueID: 10}
	translateSwap(sound)
	if sound.EntityUniqueID != 20 {
		t.Fatalf("level sound unique ID = %v, want 20", sound.EntityUniqueID)
	}

	npc := &NPCDialogue{EntityUniqueID: 10}
	translateSwap(npc)
	if npc.EntityUniqueID != 20 {
		t.Fatalf("NPC dialogue unique ID = %v, want 20", npc.EntityUniqueID)
	}

	block := &UpdateBlockSynced{EntityUniqueID: 10}
	translateSwap(block)
	if block.EntityUniqueID != 20 {
		t.Fatalf("update block synced unique ID = %v, want 20", block.EntityUniqueID)
	}

	volume := &AddVolumeEntity{EntityRuntimeID: 100}
	translateSwap(volume)
	if volume.EntityRuntimeID != 200 {
		t.Fatalf("add volume runtime ID = %v, want 200", volume.EntityRuntimeID)
	}

	removeVolume := &RemoveVolumeEntity{EntityRuntimeID: 100}
	translateSwap(removeVolume)
	if removeVolume.EntityRuntimeID != 200 {
		t.Fatalf("remove volume runtime ID = %v, want 200", removeVolume.EntityRuntimeID)
	}

	translateSwap(camera)
	if attached, _ := camera.AttachToEntity.Value(); attached != 20 {
		t.Fatalf("camera attached unique ID = %v, want 20", attached)
	}

	translateSwap(shape)
	if attached, _ := shape.Shapes[0].AttachedToEntityID.Value(); attached != 200 {
		t.Fatalf("shape attached runtime ID = %v, want 200", attached)
	}

	translateSwap(waypoint)
	if id, _ := waypoint.Waypoints[0].Waypoint.ActorUniqueID.Value(); id != 20 {
		t.Fatalf("waypoint unique ID = %v, want 20", id)
	}

	event := &Event{EntityRuntimeID: 100, Event: &protocol.MobKilledEvent{}}
	translateSwap(event)
	if event.EntityRuntimeID != 200 {
		t.Fatalf("legacy event runtime ID = %v, want 200", event.EntityRuntimeID)
	}
}
