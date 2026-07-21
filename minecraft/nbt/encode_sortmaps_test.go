package nbt

import (
	"bytes"
	"reflect"
	"testing"
)

// TestEncoderSortMaps verifies that SortMaps produces identical bytes for equal maps regardless of
// insertion order, and that the sorted output still decodes to the original value.
func TestEncoderSortMaps(t *testing.T) {
	value := map[string]any{
		"b":      "x",
		"a":      int32(1),
		"nested": map[string]any{"y": int32(2), "x": int32(1)},
		"list":   []any{map[string]any{"k2": byte(1), "k1": byte(0)}, map[string]any{"k4": byte(1), "k3": byte(0)}},
	}
	reordered := map[string]any{}
	reordered["list"] = []any{map[string]any{"k1": byte(0), "k2": byte(1)}, map[string]any{"k3": byte(0), "k4": byte(1)}}
	reordered["nested"] = map[string]any{"x": int32(1), "y": int32(2)}
	reordered["a"] = int32(1)
	reordered["b"] = "x"

	encode := func(v any) []byte {
		buf := new(bytes.Buffer)
		enc := NewEncoderWithEncoding(buf, LittleEndian)
		enc.SortMaps = true
		if err := enc.Encode(v); err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
		return buf.Bytes()
	}

	first := encode(value)
	// Equal maps must encode identically no matter how they were built; repeat to cover map ordering.
	for i := 0; i < 16; i++ {
		if second := encode(reordered); !bytes.Equal(first, second) {
			t.Fatalf("SortMaps encoding not deterministic:\n%x\n%x", first, second)
		}
	}

	var decoded map[string]any
	if err := UnmarshalEncoding(first, &decoded, LittleEndian); err != nil {
		t.Fatalf("UnmarshalEncoding() error = %v", err)
	}
	if !reflect.DeepEqual(decoded, value) {
		t.Fatalf("sorted encoding did not round-trip: got %#v, want %#v", decoded, value)
	}

	// Named string key types must stay encodable with SortMaps, like on the unsorted path.
	type namedKey string
	named := encode(map[namedKey]any{"b": int32(2), "a": int32(1)})
	plain := encode(map[string]any{"a": int32(1), "b": int32(2)})
	if !bytes.Equal(named, plain) {
		t.Fatalf("named string key encoding differs from plain string keys:\n%x\n%x", named, plain)
	}
}
