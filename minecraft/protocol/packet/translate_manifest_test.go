package packet

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// idSentinel is the value planted in each manifest field; the mapping callbacks used by
// TestTranslateEntityIDsManifestRewrites map exactly idSentinel -> idSentinel+1 for both
// ID kinds, so assertions need no per-field runtime/unique classification. It must fit
// the narrowest ID field width (uint32).
const idSentinel = 1_000_000

// idFieldFixtures constructs packets for manifest paths the reflective setter cannot
// reach or that need other fields set for the ID to be marshalled at all: values inside
// protocol.Optional, fields behind conditional flags, and enum-guarded entries. Each
// fixture returns the packet with the target field set to idSentinel and a getter that
// reads the field back after translation.
var idFieldFixtures = map[string]func() (Packet, func() int64){
	"PlayerAuthInput.ClientPredictedVehicle": func() (Packet, func() int64) {
		pk := &PlayerAuthInput{ClientPredictedVehicle: protocol.Option(int64(idSentinel))}
		return pk, func() int64 { id, _ := pk.ClientPredictedVehicle.Value(); return id }
	},
	"CameraInstruction.Target.EntityUniqueID": func() (Packet, func() int64) {
		pk := &CameraInstruction{Target: protocol.Option(protocol.CameraInstructionTarget{EntityUniqueID: idSentinel})}
		return pk, func() int64 { target, _ := pk.Target.Value(); return target.EntityUniqueID }
	},
	"CameraInstruction.AttachToEntity": func() (Packet, func() int64) {
		pk := &CameraInstruction{AttachToEntity: protocol.Option(int64(idSentinel))}
		return pk, func() int64 { attached, _ := pk.AttachToEntity.Value(); return attached }
	},
	"LocatorBar.Waypoints[].Waypoint.ActorUniqueID": func() (Packet, func() int64) {
		pk := &LocatorBar{Waypoints: []protocol.LocatorBarWaypoint{{
			Waypoint: protocol.Waypoint{ActorUniqueID: protocol.Option(int64(idSentinel))},
		}}}
		return pk, func() int64 { id, _ := pk.Waypoints[0].Waypoint.ActorUniqueID.Value(); return id }
	},
	"PrimitiveShapes.Shapes[].AttachedToEntityID": func() (Packet, func() int64) {
		pk := &PrimitiveShapes{Shapes: []protocol.PrimitiveShape{{
			AttachedToEntityID: protocol.Option(uint64(idSentinel)),
			ExtraShapeData:     &protocol.LastShape{},
		}}}
		return pk, func() int64 { id, _ := pk.Shapes[0].AttachedToEntityID.Value(); return int64(id) }
	},
	"SetScore.Entries[].EntityUniqueID": func() (Packet, func() int64) {
		pk := &SetScore{Entries: []protocol.ScoreboardEntry{{IdentityType: protocol.ScoreboardIdentityPlayer, EntityUniqueID: idSentinel}}}
		return pk, func() int64 { return pk.Entries[0].EntityUniqueID }
	},
	"SetScoreboardIdentity.Entries[].EntityUniqueID": func() (Packet, func() int64) {
		pk := &SetScoreboardIdentity{Entries: []protocol.ScoreboardIdentityEntry{{
			EntityUniqueID: protocol.Option(int64(idSentinel)),
		}}}
		return pk, func() int64 { id, _ := pk.Entries[0].EntityUniqueID.Value(); return id }
	},
	"ClientBoundMapItemData.TrackedObjects[].EntityUniqueID": func() (Packet, func() int64) {
		pk := &ClientBoundMapItemData{
			TrackedObjects: protocol.Option([]protocol.MapTrackedObject{{Type: protocol.MapObjectTypeEntity, EntityUniqueID: protocol.Option(int64(idSentinel))}}),
		}
		return pk, func() int64 {
			tracked, _ := pk.TrackedObjects.Value()
			id, _ := tracked[0].EntityUniqueID.Value()
			return id
		}
	},
	"ClientMovementPredictionSync.EntityUniqueID": func() (Packet, func() int64) {
		pk := &ClientMovementPredictionSync{ActorFlags: protocol.NewBitset(protocol.EntityDataFlagCount), EntityUniqueID: idSentinel}
		return pk, func() int64 { return pk.EntityUniqueID }
	},
	"BossEvent.PlayerUniqueID": func() (Packet, func() int64) {
		pk := &BossEvent{EventType: BossEventRegisterPlayer, PlayerUniqueID: idSentinel}
		return pk, func() int64 { return pk.PlayerUniqueID }
	},
	"Event.EntityRuntimeID": func() (Packet, func() int64) {
		pk := &Event{EntityRuntimeID: idSentinel, Event: &protocol.AchievementAwardedEvent{}}
		return pk, func() int64 { return pk.EntityRuntimeID }
	},
}

// TestTranslateEntityIDsManifestRewrites proves that every field in translatedIDFields is
// actually rewritten by TranslateEntityIDs, by planting a sentinel in the field and
// asserting the mapping callbacks were applied to it. Together with the discovery test
// this closes the loop for new packets: a conventionally named ID field must enter the
// manifest, and a manifest entry only passes when the field's Marshal routes it through
// a semantic actor-ID method.
func TestTranslateEntityIDsManifestRewrites(t *testing.T) {
	rid := func(id uint64) uint64 {
		if id == idSentinel {
			return idSentinel + 1
		}
		return id
	}
	uid := func(id int64) int64 {
		if id == idSentinel {
			return idSentinel + 1
		}
		return id
	}

	constructors := map[string]func() Packet{}
	for _, pool := range []Pool{NewClientPool(), NewServerPool()} {
		for _, newPk := range pool {
			pk := newPk()
			constructors[reflect.TypeOf(pk).Elem().Name()] = newPk
		}
	}

	for _, path := range translatedIDFields {
		t.Run(path, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("panicked: %v (field likely needs a fixture)", recovered)
				}
			}()
			var pk Packet
			var read func() int64
			if fixture, ok := idFieldFixtures[path]; ok {
				pk, read = fixture()
			} else {
				segments := strings.Split(path, ".")
				newPk, ok := constructors[segments[0]]
				if !ok {
					t.Fatalf("no registered packet named %v", segments[0])
				}
				pk = newPk()
				var err error
				read, err = plantSentinel(reflect.ValueOf(pk).Elem(), segments[1:])
				if err != nil {
					t.Fatalf("plant sentinel: %v", err)
				}
			}
			TranslateEntityIDs(pk, rid, uid)
			if got := read(); got != idSentinel+1 {
				t.Errorf("field was not translated: got %v, want %v", got, idSentinel+1)
			}
		})
	}
}

// plantSentinel walks segments below v, materialising one element for each slice hop,
// sets the target field to idSentinel and returns a getter reading it back.
func plantSentinel(v reflect.Value, segments []string) (func() int64, error) {
	segment, rest := segments[0], segments[1:]
	name, isSlice := strings.CutSuffix(segment, "[]")
	field := v.FieldByName(name)
	if !field.IsValid() {
		return nil, fmt.Errorf("%v is not a field of %v", name, v.Type())
	}
	if isSlice {
		if field.Kind() != reflect.Slice {
			return nil, fmt.Errorf("%v is not a slice", segment)
		}
		field.Set(reflect.MakeSlice(field.Type(), 1, 1))
		return plantSentinel(field.Index(0), rest)
	}
	if len(rest) > 0 {
		return plantSentinel(field, rest)
	}
	// The terminal field is either an integer ID or a slice of them (AnimateEntity).
	if field.Kind() == reflect.Slice {
		element := reflect.New(field.Type().Elem()).Elem()
		element.SetUint(idSentinel)
		field.Set(reflect.Append(field, element))
		return func() int64 { return int64(field.Index(0).Uint()) }, nil
	}
	switch field.Kind() {
	case reflect.Int32, reflect.Int64:
		field.SetInt(idSentinel)
		return func() int64 { return field.Int() }, nil
	case reflect.Uint32, reflect.Uint64:
		field.SetUint(idSentinel)
		return func() int64 { return int64(field.Uint()) }, nil
	default:
		return nil, fmt.Errorf("field %v has unsupported kind %v", segment, field.Kind())
	}
}

// tickFieldFixtures constructs packets for tick manifest paths the reflective setter
// cannot reach without other fields set for Marshal to succeed.
var tickFieldFixtures = map[string]func() (Packet, func() int64){
	"PlayerAuthInput.Tick": func() (Packet, func() int64) {
		pk := &PlayerAuthInput{Tick: idSentinel}
		return pk, func() int64 { return int64(pk.Tick) }
	},
}

// TestTranslateInputTicksManifestRewrites proves every field in translatedTickFields is
// actually rewritten by TranslateInputTicks, mirroring the entity ID manifest test.
func TestTranslateInputTicksManifestRewrites(t *testing.T) {
	tick := func(tick uint64) uint64 {
		if tick == idSentinel {
			return idSentinel + 1
		}
		return tick
	}

	constructors := map[string]func() Packet{}
	for _, pool := range []Pool{NewClientPool(), NewServerPool()} {
		for _, newPk := range pool {
			pk := newPk()
			constructors[reflect.TypeOf(pk).Elem().Name()] = newPk
		}
	}

	for _, path := range translatedTickFields {
		t.Run(path, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("panicked: %v (field likely needs a fixture)", recovered)
				}
			}()
			var pk Packet
			var read func() int64
			if fixture, ok := tickFieldFixtures[path]; ok {
				pk, read = fixture()
			} else {
				segments := strings.Split(path, ".")
				newPk, ok := constructors[segments[0]]
				if !ok {
					t.Fatalf("no registered packet named %v", segments[0])
				}
				pk = newPk()
				var err error
				read, err = plantSentinel(reflect.ValueOf(pk).Elem(), segments[1:])
				if err != nil {
					t.Fatalf("plant sentinel: %v", err)
				}
			}
			TranslateInputTicks(pk, tick)
			if got := read(); got != idSentinel+1 {
				t.Errorf("field was not translated: got %v, want %v", got, idSentinel+1)
			}
		})
	}
}
