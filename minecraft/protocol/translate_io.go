package protocol

// entityMetadataActorIDKeys holds the entity metadata keys whose values are actor unique IDs.
var entityMetadataActorIDKeys = map[uint32]struct{}{
	EntityDataKeyOwner:                    {},
	EntityDataKeyTarget:                   {},
	EntityDataKeyLeashHolder:              {},
	EntityDataKeyTargetA:                  {},
	EntityDataKeyTargetB:                  {},
	EntityDataKeyTargetC:                  {},
	EntityDataKeyTradeTarget:              {},
	EntityDataKeyBalloonAnchor:            {},
	EntityDataKeyAgent:                    {},
	EntityDataKeyAimAssistPriorityActorID: {},
	EntityDataKeyArrowShooterID:           {},
	EntityDataKeyFireworkShooterID:        {},
}

// ActorIDTranslation rewrites the actor runtime and unique IDs that flow through an IO.
type ActorIDTranslation struct {
	// RuntimeID and UniqueID map actor IDs. They must return their argument unchanged
	// for IDs they do not translate, such as sentinel values.
	RuntimeID func(uint64) uint64
	UniqueID  func(int64) int64
}

// normalised returns the translation with nil callbacks replaced by identities.
func (t ActorIDTranslation) normalised() ActorIDTranslation {
	if t.RuntimeID == nil {
		t.RuntimeID = func(id uint64) uint64 { return id }
	}
	if t.UniqueID == nil {
		t.UniqueID = func(id int64) int64 { return id }
	}
	return t
}

// WrapReader returns an IO reading through io that translates every actor ID it decodes.
func (t ActorIDTranslation) WrapReader(io IO) IO {
	return &translationReader{IO: io, t: t.normalised()}
}

// WrapWriter returns an IO encoding through io that translates every actor ID it writes,
// leaving the marshalled value unchanged.
func (t ActorIDTranslation) WrapWriter(io IO) IO {
	return &translationWriter{IO: io, t: t.normalised()}
}

// translationReader decodes through the wrapped IO and translates the decoded ID in place.
type translationReader struct {
	IO
	t ActorIDTranslation
}

func (r *translationReader) ActorRuntimeID(x *uint64) {
	r.IO.ActorRuntimeID(x)
	*x = r.t.RuntimeID(*x)
}

func (r *translationReader) ActorUniqueID(x *int64) {
	r.IO.ActorUniqueID(x)
	*x = r.t.UniqueID(*x)
}

func (r *translationReader) ActorRuntimeIDInt64(x *int64) {
	ActorRuntimeIDInt64(r.IO, x)
	*x = int64(r.t.RuntimeID(uint64(*x)))
}

func (r *translationReader) ActorRuntimeIDUint32(x *uint32) {
	ActorRuntimeIDUint32(r.IO, x)
	*x = uint32(r.t.RuntimeID(uint64(*x)))
}

func (r *translationReader) ActorUniqueIDFixed(x *int64) {
	ActorUniqueIDFixed(r.IO, x)
	*x = r.t.UniqueID(*x)
}

func (r *translationReader) ActorUniqueIDUint64(x *uint64) {
	ActorUniqueIDUint64(r.IO, x)
	*x = uint64(r.t.UniqueID(int64(*x)))
}

func (r *translationReader) ActorUniqueIDVaruint64(x *uint64) {
	ActorUniqueIDVaruint64(r.IO, x)
	*x = uint64(r.t.UniqueID(int64(*x)))
}

func (r *translationReader) EntityMetadata(x *EntityMetadata) {
	r.IO.EntityMetadata(x)
	TranslateEntityMetadataIDs(*x, r.t.UniqueID)
}

// SliceLength forwards slice length validation to the wrapped IO, keeping slice
// allocation and limit checks active behind the wrapper.
func (r *translationReader) SliceLength(value uint32, max uint32) {
	if limit, ok := r.IO.(sliceReader); ok {
		limit.SliceLength(value, max)
	}
}

// translationWriter encodes a translated copy of each actor ID through the wrapped IO.
type translationWriter struct {
	IO
	t ActorIDTranslation
}

func (w *translationWriter) ActorRuntimeID(x *uint64) {
	v := w.t.RuntimeID(*x)
	w.IO.ActorRuntimeID(&v)
}

func (w *translationWriter) ActorUniqueID(x *int64) {
	v := w.t.UniqueID(*x)
	w.IO.ActorUniqueID(&v)
}

func (w *translationWriter) ActorRuntimeIDInt64(x *int64) {
	v := int64(w.t.RuntimeID(uint64(*x)))
	ActorRuntimeIDInt64(w.IO, &v)
}

func (w *translationWriter) ActorRuntimeIDUint32(x *uint32) {
	v := uint32(w.t.RuntimeID(uint64(*x)))
	ActorRuntimeIDUint32(w.IO, &v)
}

func (w *translationWriter) ActorUniqueIDFixed(x *int64) {
	v := w.t.UniqueID(*x)
	ActorUniqueIDFixed(w.IO, &v)
}

func (w *translationWriter) ActorUniqueIDUint64(x *uint64) {
	v := uint64(w.t.UniqueID(int64(*x)))
	ActorUniqueIDUint64(w.IO, &v)
}

func (w *translationWriter) ActorUniqueIDVaruint64(x *uint64) {
	v := uint64(w.t.UniqueID(int64(*x)))
	ActorUniqueIDVaruint64(w.IO, &v)
}

func (w *translationWriter) EntityMetadata(x *EntityMetadata) {
	translated := make(EntityMetadata, len(*x))
	for key, value := range *x {
		translated[key] = value
	}
	TranslateEntityMetadataIDs(translated, w.t.UniqueID)
	w.IO.EntityMetadata(&translated)
}

// TranslateEntityMetadataIDs passes every metadata value holding an actor unique ID
// through unique, storing the results.
func TranslateEntityMetadataIDs(m EntityMetadata, unique func(int64) int64) {
	for key := range entityMetadataActorIDKeys {
		switch id := m[key].(type) {
		case int64:
			m[key] = unique(id)
		case uint64:
			m[key] = uint64(unique(int64(id)))
		}
	}
}
