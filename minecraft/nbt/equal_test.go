package nbt

import (
	"math"
	"testing"
)

func TestCompound_EqualDecodedValueSemantics(t *testing.T) {
	for _, test := range []struct {
		name string
		a, b Compound
		want bool
	}{
		{"nil", nil, nil, true},
		{"nil and empty compound", nil, map[string]any{}, false},
		{"different key", map[string]any{"a": int32(1)}, map[string]any{"b": int32(1)}, false},
		{"scalar type", map[string]any{"a": int32(1)}, map[string]any{"a": int64(1)}, false},
		{"nested nil and empty", map[string]any{"a": map[string]any(nil)}, map[string]any{"a": map[string]any{}}, false},
		{"nil and empty list", map[string]any{"a": []any(nil)}, map[string]any{"a": []any{}}, false},
		{"list type", map[string]any{"a": []string{"text"}}, map[string]any{"a": []any{"text"}}, false},
		{"byte list", map[string]any{"a": []byte{1}}, map[string]any{"a": []byte{1}}, true},
		{"int list", map[string]any{"a": []int32{1}}, map[string]any{"a": []int32{1}}, true},
		{"long list", map[string]any{"a": []int64{1}}, map[string]any{"a": []int64{2}}, false},
		{"value array", map[string]any{"a": [2]int32{1, 2}}, map[string]any{"a": [2]int32{1, 2}}, true},
		{"nested list", map[string]any{"a": []any{map[string]any{"b": "text"}}}, map[string]any{"a": []any{map[string]any{"b": "text"}}}, true},
		{"named compound", Compound{"a": Compound{"b": "text"}}, Compound{"a": Compound{"b": "text"}}, true},
		{"nested compound type", Compound{"a": Compound{"b": "text"}}, Compound{"a": map[string]any{"b": "text"}}, false},
		{"NaN", map[string]any{"a": math.NaN()}, map[string]any{"a": math.NaN()}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.a.Equal(test.b); got != test.want {
				t.Fatalf("Equal = %v; want %v", got, test.want)
			}
			if got := test.b.Equal(test.a); got != test.want {
				t.Fatalf("reverse Equal = %v; want %v", got, test.want)
			}
		})
	}
}

func TestCompound_EqualDecodedContainersDoNotAllocate(t *testing.T) {
	first := Compound{
		"compound": map[string]any{"number": int32(1)},
		"list":     []any{map[string]any{"name": "value"}},
		"bytes":    []byte{1, 2}, "ints": []int32{3, 4}, "longs": []int64{5, 6}, "array": [2]int32{7, 8},
	}
	second := first.Clone()
	if allocations := testing.AllocsPerRun(100, func() {
		if !first.Equal(second) {
			t.Fatal("equal decoded compounds compared unequal")
		}
	}); allocations != 0 {
		t.Fatalf("Equal allocated %.0f objects; want zero", allocations)
	}
}
