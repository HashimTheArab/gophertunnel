package packet

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

func TestBlockActorData_DefaultDecodePreservesNBTDataMap(t *testing.T) {
	t.Parallel()

	wire := blockActorDataGoldenWire()
	var got BlockActorData
	got.Marshal(protocol.NewReader(bytes.NewBuffer(wire), 0, true))
	want := map[string]any{"CustomName": "loot", "pairx": int32(2), "pairz": int32(-2)}
	if !reflect.DeepEqual(got.NBTData, want) {
		t.Fatalf("default NBTData = %#v, want %#v", got.NBTData, want)
	}
}

func TestBlockActorData_LazyDecodeForwardsGoldenWireExactly(t *testing.T) {
	t.Parallel()

	wire := blockActorDataGoldenWire()
	got := NewLazyBlockActorData()
	got.Marshal(protocol.NewReader(bytes.NewBuffer(wire), 0, true))
	if got.NBTData != nil {
		t.Fatalf("lazy NBTData = %#v, want nil before materialisation", got.NBTData)
	}
	fields, err := got.NBTFields("pairx", "pairz")
	if err != nil {
		t.Fatalf("NBTFields() error = %v", err)
	}
	if want := map[string]any{"pairx": int32(2), "pairz": int32(-2)}; !reflect.DeepEqual(fields, want) {
		t.Fatalf("NBTFields() = %#v, want %#v", fields, want)
	}

	var encoded bytes.Buffer
	got.Marshal(protocol.NewWriter(&encoded, 0))
	if !bytes.Equal(encoded.Bytes(), wire) {
		t.Fatalf("forwarded wire = %x, want golden %x", encoded.Bytes(), wire)
	}
}

func TestBlockActorData_LazyDecodeMaterialisedMutationEncodesMap(t *testing.T) {
	t.Parallel()

	got := NewLazyBlockActorData()
	got.Marshal(protocol.NewReader(bytes.NewBuffer(blockActorDataGoldenWire()), 0, true))
	if err := got.MaterialiseNBT(); err != nil {
		t.Fatalf("MaterialiseNBT() error = %v", err)
	}
	got.NBTData["CustomName"] = "changed"

	var encoded bytes.Buffer
	got.Marshal(protocol.NewWriter(&encoded, 0))
	var decoded BlockActorData
	decoded.Marshal(protocol.NewReader(bytes.NewBuffer(encoded.Bytes()), 0, true))
	if decoded.NBTData["CustomName"] != "changed" {
		t.Fatalf("mutated CustomName = %#v, want %q", decoded.NBTData["CustomName"], "changed")
	}
}

func TestBlockActorData_LazyDecodeMaterialisedNilEncodesEmptyCompound(t *testing.T) {
	t.Parallel()

	got := NewLazyBlockActorData()
	got.Marshal(protocol.NewReader(bytes.NewBuffer(blockActorDataGoldenWire()), 0, true))
	if err := got.MaterialiseNBT(); err != nil {
		t.Fatalf("MaterialiseNBT() error = %v", err)
	}
	got.NBTData = nil

	var encoded bytes.Buffer
	got.Marshal(protocol.NewWriter(&encoded, 0))
	var decoded BlockActorData
	decoded.Marshal(protocol.NewReader(bytes.NewBuffer(encoded.Bytes()), 0, true))
	if decoded.NBTData == nil || len(decoded.NBTData) != 0 {
		t.Fatalf("decoded NBTData = %#v, want non-nil empty map", decoded.NBTData)
	}
}

func TestBlockActorData_LazyZeroNBTMaterialisesAsEmptyMap(t *testing.T) {
	t.Parallel()

	wire := []byte{0x02, 0x80, 0x01, 0x03, 0x00}
	got := NewLazyBlockActorData()
	got.Marshal(protocol.NewReader(bytes.NewBuffer(wire), 0, true))
	if err := got.MaterialiseNBT(); err != nil {
		t.Fatalf("MaterialiseNBT() error = %v", err)
	}
	if got.NBTData == nil || len(got.NBTData) != 0 {
		t.Fatalf("materialised zero NBTData = %#v, want non-nil empty map", got.NBTData)
	}
}

func TestBlockActorData_LazyDecodeWorksThroughTranslationIO(t *testing.T) {
	t.Parallel()

	wire := blockActorDataGoldenWire()
	translation := protocol.ActorIDTranslation{}
	got := NewLazyBlockActorData()
	got.Marshal(translation.WrapReader(protocol.NewReader(bytes.NewBuffer(wire), 0, true)))
	var encoded bytes.Buffer
	got.Marshal(translation.WrapWriter(protocol.NewWriter(&encoded, 0)))
	if !bytes.Equal(encoded.Bytes(), wire) {
		t.Fatalf("translated forwarded wire = %x, want %x", encoded.Bytes(), wire)
	}
}

func TestBlockActorData_LazyDecodeRejectsNonCompoundNBT(t *testing.T) {
	t.Parallel()

	wire := []byte{0x02, 0x80, 0x01, 0x03, 0x01, 0x00, 0x01}
	defer func() {
		if recover() == nil {
			t.Fatal("lazy decode accepted a non-compound NBT root")
		}
	}()
	NewLazyBlockActorData().Marshal(protocol.NewReader(bytes.NewBuffer(wire), 0, true))
}

func BenchmarkBlockActorDataDecodeForward(b *testing.B) {
	wire := representativeBlockActorDataWire(b)
	b.ReportAllocs()
	b.Run("eager", func(b *testing.B) {
		for b.Loop() {
			var pk BlockActorData
			pk.Marshal(protocol.NewReader(bytes.NewBuffer(wire), 0, true))
			var dst bytes.Buffer
			pk.Marshal(protocol.NewWriter(&dst, 0))
		}
	})
	b.Run("lazy-retained-fields", func(b *testing.B) {
		for b.Loop() {
			pk := NewLazyBlockActorData()
			pk.Marshal(protocol.NewReader(bytes.NewBuffer(wire), 0, true))
			if _, err := pk.NBTFields("pairx", "pairz", "Base", "Patterns", "Type", "sherds", "ItemRotation", "color"); err != nil {
				b.Fatal(err)
			}
			var dst bytes.Buffer
			pk.Marshal(protocol.NewWriter(&dst, 0))
		}
	})
}

// blockActorDataGoldenWire returns a fixed valid BlockActorData payload whose
// NBT key order is intentionally part of the golden.
func blockActorDataGoldenWire() []byte {
	return []byte{
		0x02, 0x80, 0x01, 0x03,
		0x0a, 0x00,
		0x08, 0x0a, 'C', 'u', 's', 't', 'o', 'm', 'N', 'a', 'm', 'e', 0x04, 'l', 'o', 'o', 't',
		0x03, 0x05, 'p', 'a', 'i', 'r', 'x', 0x04,
		0x03, 0x05, 'p', 'a', 'i', 'r', 'z', 0x03,
		0x00,
	}
}

// representativeBlockActorDataWire returns a large container-style payload
// for comparing eager and raw-backed decode/forward costs.
func representativeBlockActorDataWire(tb testing.TB) []byte {
	tb.Helper()
	items := make([]any, 128)
	for i := range items {
		items[i] = map[string]any{
			"Name":   "minecraft:diamond_sword",
			"Count":  uint8(1),
			"Damage": int32(i),
			"tag": map[string]any{
				"display": map[string]any{"Name": "a deliberately large item name"},
			},
		}
	}
	pk := &BlockActorData{
		Position: protocol.BlockPos{1, 64, -2},
		NBTData: map[string]any{
			"CustomName": "large fixture",
			"Items":      items,
			"pairx":      int32(2),
			"pairz":      int32(-3),
			"Patterns": []any{
				map[string]any{"Pattern": "bri", "Color": int32(1)},
			},
		},
	}
	var buf bytes.Buffer
	pk.Marshal(protocol.NewWriter(&buf, 0))
	return buf.Bytes()
}
