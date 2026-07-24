package packet

import (
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

func TestEntityIdentityTranslator_SwapsBothDirections(t *testing.T) {
	translator := NewEntityIdentityTranslator(7, 70)
	translator.SetCurrent(9, 90)

	replacement := &AddPlayer{
		EntityRuntimeID: 9,
		AbilityData:     protocol.AbilityData{EntityUniqueID: 90},
	}
	translator.Translate(replacement)
	if replacement.EntityRuntimeID != 7 || replacement.AbilityData.EntityUniqueID != 70 {
		t.Fatalf("replacement identity = %d/%d, want 7/70",
			replacement.EntityRuntimeID, replacement.AbilityData.EntityUniqueID)
	}

	retained := &PlayerAction{EntityRuntimeID: 7}
	translator.Translate(retained)
	if retained.EntityRuntimeID != 9 {
		t.Fatalf("retained runtime ID = %d, want 9", retained.EntityRuntimeID)
	}
}

func TestEntityIdentityTranslator_PreservesCollidingActor(t *testing.T) {
	translator := NewEntityIdentityTranslator(7, 70)
	translator.SetCurrent(9, 90)

	actor := &AddActor{EntityRuntimeID: 7, EntityUniqueID: 70}
	translator.Translate(actor)
	if actor.EntityRuntimeID != 9 || actor.EntityUniqueID != 90 {
		t.Fatalf("colliding actor identity = %d/%d, want 9/90", actor.EntityRuntimeID, actor.EntityUniqueID)
	}
}

func TestEntityIdentityTranslator_TranslatesNestedIdentities(t *testing.T) {
	translator := NewEntityIdentityTranslator(7, 70)
	translator.SetCurrent(9, 90)

	t.Run("camera", func(t *testing.T) {
		instruction := &CameraInstruction{
			Target:         protocol.Option(protocol.CameraInstructionTarget{EntityUniqueID: 90}),
			AttachToEntity: protocol.Option[int64](90),
		}
		translator.Translate(instruction)

		target, targetSet := instruction.Target.Value()
		attached, attachedSet := instruction.AttachToEntity.Value()
		if !targetSet || target.EntityUniqueID != 70 || !attachedSet || attached != 70 {
			t.Fatalf("camera identities = target %d/%t attached %d/%t, want 70",
				target.EntityUniqueID, targetSet, attached, attachedSet)
		}
	})

	t.Run("metadata", func(t *testing.T) {
		metadata := protocol.EntityMetadata{
			protocol.EntityDataKeyOwner:             int64(90),
			protocol.EntityDataKeyBaseRuntimeID:     uint64(9),
			protocol.EntityDataKeyVisibleMobEffects: int64(9),
		}
		translator.Translate(&SetActorData{EntityMetadata: metadata})
		if got := metadata[protocol.EntityDataKeyOwner]; got != int64(70) {
			t.Errorf("owner metadata = %#v, want 70", got)
		}
		if got := metadata[protocol.EntityDataKeyBaseRuntimeID]; got != uint64(7) {
			t.Errorf("base runtime metadata = %#v, want 7", got)
		}
		if got := metadata[protocol.EntityDataKeyVisibleMobEffects]; got != int64(9) {
			t.Errorf("unrelated metadata = %#v, want 9", got)
		}
	})

	t.Run("primitive shape", func(t *testing.T) {
		shapes := &PrimitiveShapes{Shapes: []protocol.PrimitiveShape{
			{AttachedToEntityID: protocol.Option[int64](90)},
			{},
		}}
		translator.Translate(shapes)

		id, ok := shapes.Shapes[0].AttachedToEntityID.Value()
		if !ok || id != 70 {
			t.Fatalf("attached entity identity = %d/%t, want 70", id, ok)
		}
		if _, ok := shapes.Shapes[1].AttachedToEntityID.Value(); ok {
			t.Fatal("unset attached entity identity became set")
		}
	})

	t.Run("interaction event", func(t *testing.T) {
		event := &Event{
			EntityRuntimeID: 9,
			Event:           &protocol.EntityInteractEvent{InteractedEntityID: 90},
		}
		translator.Translate(event)
		if event.EntityRuntimeID != 7 || event.Event.(*protocol.EntityInteractEvent).InteractedEntityID != 70 {
			t.Fatalf("event identities = %d/%d, want 7/70",
				event.EntityRuntimeID, event.Event.(*protocol.EntityInteractEvent).InteractedEntityID)
		}
	})
}

func TestEntityIdentityTranslator_RespectsConditionalIdentities(t *testing.T) {
	translator := NewEntityIdentityTranslator(7, 70)
	translator.SetCurrent(9, 90)

	input := &PlayerAuthInput{
		InputData:              protocol.NewBitset(PlayerAuthInputBitsetSize),
		ClientPredictedVehicle: 70,
	}
	translator.Translate(input)
	if input.ClientPredictedVehicle != 70 {
		t.Fatalf("inactive predicted vehicle identity = %d, want 70", input.ClientPredictedVehicle)
	}
	input.InputData.Set(InputFlagClientPredictedVehicle)
	translator.Translate(input)
	if input.ClientPredictedVehicle != 90 {
		t.Fatalf("active predicted vehicle identity = %d, want 90", input.ClientPredictedVehicle)
	}

	scores := &SetScore{Entries: []protocol.ScoreboardEntry{
		{IdentityType: protocol.ScoreboardIdentityFakePlayer, EntityUniqueID: 70},
		{IdentityType: protocol.ScoreboardIdentityPlayer, EntityUniqueID: 70},
	}}
	translator.Translate(scores)
	if scores.Entries[0].EntityUniqueID != 70 || scores.Entries[1].EntityUniqueID != 90 {
		t.Fatalf("score identities = %d/%d, want 70/90",
			scores.Entries[0].EntityUniqueID, scores.Entries[1].EntityUniqueID)
	}
}

func TestEntityIdentityTranslator_SetCurrent(t *testing.T) {
	translator := NewEntityIdentityTranslator(7, 70)

	unchanged := &StartGame{EntityRuntimeID: 7, EntityUniqueID: 70}
	translator.Translate(unchanged)
	if unchanged.EntityRuntimeID != 7 || unchanged.EntityUniqueID != 70 {
		t.Fatalf("initial identity = %d/%d, want 7/70", unchanged.EntityRuntimeID, unchanged.EntityUniqueID)
	}

	translator.SetCurrent(11, 110)
	current := &StartGame{EntityRuntimeID: 11, EntityUniqueID: 110}
	translator.Translate(current)
	if current.EntityRuntimeID != 7 || current.EntityUniqueID != 70 {
		t.Fatalf("updated identity = %d/%d, want 7/70", current.EntityRuntimeID, current.EntityUniqueID)
	}
}

func TestEntityIdentityTranslator_ZeroValue(t *testing.T) {
	var translator EntityIdentityTranslator
	game := &StartGame{EntityRuntimeID: 7, EntityUniqueID: 70}
	translator.Translate(game)
	if game.EntityRuntimeID != 7 || game.EntityUniqueID != 70 {
		t.Fatalf("identity = %d/%d, want 7/70", game.EntityRuntimeID, game.EntityUniqueID)
	}
}
