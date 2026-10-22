package nbt

import (
	"reflect"
	"slices"
)

// Equal compares decoded NBT compounds without copying them. Types and nil
// containers are significant: a nil compound or list differs from an empty one,
// and typed lists differ from []any lists. The container fast paths avoid the
// allocations of reflect.DeepEqual for separately decoded compounds.
func (a Compound) Equal(b Compound) bool {
	if (a == nil) != (b == nil) || len(a) != len(b) {
		return false
	}
	for name, value := range a {
		other, ok := b[name]
		if !ok || !equalValue(value, other) {
			return false
		}
	}
	return true
}

// equalValue handles the decoder's reference containers directly. Other typed
// values retain DeepEqual's comparison semantics, including value arrays.
func equalValue(a, b any) bool {
	switch a := a.(type) {
	case Compound:
		b, ok := b.(Compound)
		return ok && a.Equal(b)
	case map[string]any:
		b, ok := b.(map[string]any)
		return ok && Compound(a).Equal(b)
	case []any:
		b, ok := b.([]any)
		if !ok || (a == nil) != (b == nil) || len(a) != len(b) {
			return false
		}
		for i := range a {
			if !equalValue(a[i], b[i]) {
				return false
			}
		}
		return true
	case []byte:
		b, ok := b.([]byte)
		return ok && (a == nil) == (b == nil) && slices.Equal(a, b)
	case []int32:
		b, ok := b.([]int32)
		return ok && (a == nil) == (b == nil) && slices.Equal(a, b)
	case []int64:
		b, ok := b.([]int64)
		return ok && (a == nil) == (b == nil) && slices.Equal(a, b)
	default:
		return reflect.DeepEqual(a, b)
	}
}
