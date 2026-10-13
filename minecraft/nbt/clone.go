package nbt

import "reflect"

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
		cloned[name] = cloneValue(reflect.ValueOf(value)).Interface()
	}
	return cloned
}

// cloneValue copies decoded compound and list containers without a parallel
// list of the decoder's concrete slice and array types.
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
