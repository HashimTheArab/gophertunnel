package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// entityMetadataIDKeys holds the entity metadata keys whose values are entity unique IDs.
var entityMetadataIDKeys = map[uint32]struct{}{
	protocol.EntityDataKeyOwner:                    {},
	protocol.EntityDataKeyTarget:                   {},
	protocol.EntityDataKeyLeashHolder:              {},
	protocol.EntityDataKeyTargetA:                  {},
	protocol.EntityDataKeyTargetB:                  {},
	protocol.EntityDataKeyTargetC:                  {},
	protocol.EntityDataKeyTradeTarget:              {},
	protocol.EntityDataKeyBalloonAnchor:            {},
	protocol.EntityDataKeyAgent:                    {},
	protocol.EntityDataKeyAimAssistPriorityActorID: {},
	protocol.EntityDataKeyArrowShooterID:           {},
	protocol.EntityDataKeyFireworkShooterID:        {},
}

// TranslateEntityIDs passes every entity runtime ID and entity unique ID carried by pk,
// including IDs nested in structures such as entity links or metadata, through runtimeID
// and uniqueID respectively, storing the results. Either function may be nil to leave IDs
// of that kind untouched. The callbacks decide the mapping policy and must return their
// argument unchanged for IDs they do not translate, such as sentinel values like math.MaxInt64.
// IDs held in fields narrower than 64 bits are truncated to the field's width, matching
// their wire encoding: IDs that do not fit cannot be represented by those packets at all.
//
// The traversal runs pk's own Marshal and therefore has writer semantics: a packet a
// Writer would reject, such as one with a nil interface field, panics here the same way,
// and fields a packet's flags exclude from the wire may be normalised (zeroed) exactly as
// writing the packet would normalise them.
func TranslateEntityIDs(pk Packet, runtimeID func(uint64) uint64, uniqueID func(int64) int64) {
	if runtimeID == nil {
		runtimeID = func(id uint64) uint64 { return id }
	}
	if uniqueID == nil {
		uniqueID = func(id int64) int64 { return id }
	}

	visitor := translatingIO{
		IO:        protocol.NewWriter(discardWriter{}, 0),
		runtime:   runtimeID,
		unique:    uniqueID,
		inputTick: func(tick uint64) uint64 { return tick },
	}
	pk.Marshal(&visitor)
}

// TranslateInputTicks passes every player input tick carried by pk through tick, storing
// the results. The callback must return its argument unchanged for ticks it does not
// translate, such as the zero marking a field without an input tick reference. The
// traversal has writer semantics, exactly as documented on TranslateEntityIDs.
func TranslateInputTicks(pk Packet, tick func(uint64) uint64) {
	if tick == nil {
		return
	}
	visitor := translatingIO{
		IO:        protocol.NewWriter(discardWriter{}, 0),
		runtime:   func(id uint64) uint64 { return id },
		unique:    func(id int64) int64 { return id },
		inputTick: tick,
	}
	pk.Marshal(&visitor)
}

// translatingIO delegates ordinary packet traversal to a discard writer and intercepts
// only the semantic actor-ID operations. The packet's own Marshal method therefore owns
// field order, conditionals, slices and interface dispatch.
type translatingIO struct {
	protocol.IO
	runtime   func(uint64) uint64
	unique    func(int64) int64
	inputTick func(uint64) uint64
}

func (io *translatingIO) ActorRuntimeID(x *uint64) {
	*x = io.runtime(*x)
}

func (io *translatingIO) PlayerInputTick(x *uint64) {
	*x = io.inputTick(*x)
}

func (io *translatingIO) ActorUniqueID(x *int64) {
	*x = io.unique(*x)
}

// The following methods are used by protocol helpers for fields whose wire encoding
// predates the canonical actor-ID varints. They intentionally do not encode anything:
// TranslateEntityIDs traverses with a discard writer, so they only apply the mapping.
func (io *translatingIO) ActorRuntimeIDInt64(x *int64) {
	*x = int64(io.runtime(uint64(*x)))
}

func (io *translatingIO) ActorRuntimeIDUint32(x *uint32) {
	*x = uint32(io.runtime(uint64(*x)))
}

func (io *translatingIO) ActorUniqueIDFixed(x *int64) {
	*x = io.unique(*x)
}

func (io *translatingIO) ActorUniqueIDUint64(x *uint64) {
	*x = uint64(io.unique(int64(*x)))
}

func (io *translatingIO) ActorUniqueIDVaruint64(x *uint64) {
	*x = uint64(io.unique(int64(*x)))
}

func (io *translatingIO) EntityMetadata(x *protocol.EntityMetadata) {
	for key, value := range *x {
		if _, ok := entityMetadataIDKeys[key]; !ok {
			continue
		}
		switch id := value.(type) {
		case int64:
			(*x)[key] = io.unique(id)
		case uint64:
			(*x)[key] = uint64(io.unique(int64(id)))
		}
	}
}

// discardWriter lets the normal Writer traverse packet structure without allocating or
// retaining an encoded copy of the packet.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func (discardWriter) WriteByte(byte) error { return nil }
