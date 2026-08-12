package protocol

import (
	"bytes"
	"testing"
)

// actorIDFields exercises every semantic actor ID operation, entity metadata and one
// non-ID field that must pass through untranslated.
type actorIDFields struct {
	Runtime         uint64
	Unique          int64
	RuntimeInt64    int64
	RuntimeUint32   uint32
	UniqueFixed     int64
	UniqueUint64    uint64
	UniqueVaruint64 uint64
	Metadata        EntityMetadata
	Links           []EntityLink
	Other           uint64
}

func (a *actorIDFields) Marshal(io IO) {
	io.ActorRuntimeID(&a.Runtime)
	io.ActorUniqueID(&a.Unique)
	io.ActorRuntimeIDVarint64(&a.RuntimeInt64)
	io.ActorRuntimeIDVaruint32(&a.RuntimeUint32)
	io.ActorUniqueIDInt64(&a.UniqueFixed)
	io.ActorUniqueIDUint64(&a.UniqueUint64)
	io.ActorUniqueIDVaruint64(&a.UniqueVaruint64)
	io.EntityMetadata(&a.Metadata)
	Slice(io, &a.Links)
	io.Varuint64(&a.Other)
}

// testTranslation maps runtime ID 100 <-> 200 and unique ID 10 <-> 20.
func testTranslation() *ActorIDTranslation {
	return &ActorIDTranslation{
		RuntimeID: func(id uint64) uint64 {
			switch id {
			case 100:
				return 200
			case 200:
				return 100
			}
			return id
		},
		UniqueID: func(id int64) int64 {
			switch id {
			case 10:
				return 20
			case 20:
				return 10
			}
			return id
		},
	}
}

func untranslated() *actorIDFields {
	return &actorIDFields{
		Runtime:         100,
		Unique:          10,
		RuntimeInt64:    200,
		RuntimeUint32:   100,
		UniqueFixed:     20,
		UniqueUint64:    10,
		UniqueVaruint64: 20,
		Metadata: EntityMetadata{
			EntityDataKeyOwner:  int64(10),
			EntityDataKeyTarget: int64(20),
			EntityDataKeyName:   "unrelated",
		},
		Links: []EntityLink{{RiddenEntityUniqueID: 10, RiderEntityUniqueID: 20}},
		Other: 100,
	}
}

func assertTranslated(t *testing.T, got *actorIDFields) {
	t.Helper()
	if got.Runtime != 200 || got.RuntimeInt64 != 100 || got.RuntimeUint32 != 200 {
		t.Errorf("runtime IDs not translated: %+v", got)
	}
	if got.Unique != 20 || got.UniqueFixed != 10 || got.UniqueUint64 != 20 || got.UniqueVaruint64 != 10 {
		t.Errorf("unique IDs not translated: %+v", got)
	}
	if owner := got.Metadata[EntityDataKeyOwner]; owner != int64(20) {
		t.Errorf("owner metadata not translated: %v", owner)
	}
	if target := got.Metadata[EntityDataKeyTarget]; target != int64(10) {
		t.Errorf("target metadata not translated: %v", target)
	}
	if name := got.Metadata[EntityDataKeyName]; name != "unrelated" {
		t.Errorf("unrelated metadata changed: %v", name)
	}
	if len(got.Links) != 1 || got.Links[0].RiddenEntityUniqueID != 20 || got.Links[0].RiderEntityUniqueID != 10 {
		t.Errorf("entity links not decoded and translated: %+v", got.Links)
	}
	if got.Other != 100 {
		t.Errorf("non-ID field translated: %v", got.Other)
	}
}

func TestActorIDTranslationWrapWriter(t *testing.T) {
	src := untranslated()
	buf := new(bytes.Buffer)
	src.Marshal(testTranslation().WrapWriter(NewWriter(buf, 0)))

	original := untranslated()
	if src.Runtime != original.Runtime || src.Unique != original.Unique || src.Metadata[EntityDataKeyOwner] != int64(10) {
		t.Errorf("writing mutated the marshalled value: %+v", src)
	}

	var got actorIDFields
	got.Marshal(NewReader(buf, 0, true))
	assertTranslated(t, &got)
}

func TestActorIDTranslationWrapReader(t *testing.T) {
	buf := new(bytes.Buffer)
	untranslated().Marshal(NewWriter(buf, 0))

	var got actorIDFields
	got.Marshal(testTranslation().WrapReader(NewReader(buf, 0, true)))
	assertTranslated(t, &got)
}

func TestActorIDTranslationNilCallbacks(t *testing.T) {
	buf := new(bytes.Buffer)
	untranslated().Marshal((&ActorIDTranslation{}).WrapWriter(NewWriter(buf, 0)))

	var got actorIDFields
	got.Marshal(NewReader(buf, 0, true))
	want := untranslated()
	if got.Runtime != want.Runtime || got.Unique != want.Unique || got.UniqueFixed != want.UniqueFixed {
		t.Errorf("nil callbacks changed IDs: %+v", got)
	}
}
