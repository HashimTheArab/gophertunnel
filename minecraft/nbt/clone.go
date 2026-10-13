package nbt

import (
	"reflect"
	"slices"
)

// Clone returns an independently owned copy of a decoded NBT compound. It
// preserves scalar values, array and list types, and nil maps and slices. It
// does not encode or normalise values. The compound must contain acyclic values
// decoded into map[string]any by Unmarshal, or equivalent typed lists and arrays.
func Clone(compound map[string]any) map[string]any {
	if compound == nil {
		return nil
	}
	cloned := make(map[string]any, len(compound))
	for name, value := range compound {
		cloned[name] = cloneDecodedValue(value)
	}
	return cloned
}

// cloneDecodedValue avoids reflection allocations for common decoded containers
// while retaining structural copying for other typed lists and arrays.
func cloneDecodedValue(value any) any {
	switch value := value.(type) {
	case map[string]any:
		return Clone(value)
	case []any:
		if value == nil {
			return value
		}
		cloned := make([]any, len(value))
		for i, element := range value {
			cloned[i] = cloneDecodedValue(element)
		}
		return cloned
	case []byte:
		return slices.Clone(value)
	case []int32:
		return slices.Clone(value)
	case []int64:
		return slices.Clone(value)
	default:
		reflected := reflect.ValueOf(value)
		if reflected.IsValid() && containerType(reflected.Type()) {
			return cloneValue(reflected).Interface()
		}
		return value
	}
}

// cloneValue detaches uncommon typed containers without an exhaustive type list.
func cloneValue(value reflect.Value) reflect.Value {
	if !value.IsValid() {
		return reflect.Zero(reflect.TypeFor[any]())
	}
	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return value
		}
		cloned := reflect.New(value.Type()).Elem()
		cloned.Set(cloneValue(value.Elem()))
		return cloned
	case reflect.Map:
		if value.IsNil() {
			return value
		}
		cloned := reflect.MakeMapWithSize(value.Type(), value.Len())
		entries := value.MapRange()
		for entries.Next() {
			cloned.SetMapIndex(entries.Key(), cloneValue(entries.Value()))
		}
		return cloned
	case reflect.Slice:
		if value.IsNil() {
			return value
		}
		cloned := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		reflect.Copy(cloned, value)
		if containerType(value.Type().Elem()) {
			for i := range value.Len() {
				cloned.Index(i).Set(cloneValue(value.Index(i)))
			}
		}
		return cloned
	case reflect.Array:
		if !containerType(value.Type().Elem()) {
			return value
		}
		cloned := reflect.New(value.Type()).Elem()
		for i := range value.Len() {
			cloned.Index(i).Set(cloneValue(value.Index(i)))
		}
		return cloned
	default:
		return value
	}
}

// containerType reports whether list or array elements can themselves hold
// compound or list containers.
func containerType(valueType reflect.Type) bool {
	switch valueType.Kind() {
	case reflect.Interface, reflect.Map, reflect.Slice, reflect.Array:
		return true
	}
	return false
}
