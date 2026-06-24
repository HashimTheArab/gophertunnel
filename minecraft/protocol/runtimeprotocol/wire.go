package runtimeprotocol

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

type wireType struct {
	read  func(protocol.IO) any
	write func(protocol.IO, any)
}

func wire[T any](ioFunc func(protocol.IO, *T), coerce func(any) T) wireType {
	return wireType{
		read: func(io protocol.IO) any {
			var v T
			ioFunc(io, &v)
			return v
		},
		write: func(io protocol.IO, value any) {
			v := coerce(value)
			ioFunc(io, &v)
		},
	}
}

var (
	wireBool      = wire(protocol.IO.Bool, asBool)
	wireString    = wire(protocol.IO.String, asString)
	wireUint8     = wire(protocol.IO.Uint8, func(v any) uint8 { return uint8(asUint64(v)) })
	wireInt8      = wire(protocol.IO.Int8, func(v any) int8 { return int8(asInt64(v)) })
	wireUint16    = wire(protocol.IO.Uint16, func(v any) uint16 { return uint16(asUint64(v)) })
	wireInt16     = wire(protocol.IO.Int16, func(v any) int16 { return int16(asInt64(v)) })
	wireUint32    = wire(protocol.IO.Uint32, func(v any) uint32 { return uint32(asUint64(v)) })
	wireInt32     = wire(protocol.IO.Int32, func(v any) int32 { return int32(asInt64(v)) })
	wireBEInt32   = wire(protocol.IO.BEInt32, func(v any) int32 { return int32(asInt64(v)) })
	wireVaruint32 = wire(protocol.IO.Varuint32, func(v any) uint32 { return uint32(asUint64(v)) })
	wireVarint32  = wire(protocol.IO.Varint32, func(v any) int32 { return int32(asInt64(v)) })
	wireUint64    = wire(protocol.IO.Uint64, asUint64)
	wireInt64     = wire(protocol.IO.Int64, asInt64)
	wireVaruint64 = wire(protocol.IO.Varuint64, asUint64)
	wireVarint64  = wire(protocol.IO.Varint64, asInt64)
	wireFloat32   = wire(protocol.IO.Float32, func(v any) float32 { return float32(asFloat64(v)) })
	wireFloat64   = wire(protocol.IO.Float64, asFloat64)
)

func (w wireType) decode(io protocol.IO) any {
	return w.read(io)
}

func (w wireType) encode(io protocol.IO, value any) {
	w.write(io, value)
}

func decodeFields(io protocol.IO, fields []fieldSpec, values map[string]any) {
	for _, field := range fields {
		values[field.name] = field.decode(io)
	}
}

func encodeFields(io protocol.IO, fields []fieldSpec, values map[string]any) {
	for _, field := range fields {
		field.encode(io, values[field.name])
	}
}

func scalarWire(node rawNode) (wireType, error) {
	if isEnumAsValue(node) {
		return integerWire(node.UnderlyingType, node.SerializationOptions)
	}
	switch node.Type {
	case "boolean":
		return wireBool, nil
	case "string":
		return wireString, nil
	case "number":
		switch node.UnderlyingType {
		case "", "float", "float32":
			return wireFloat32, nil
		case "float64":
			return wireFloat64, nil
		default:
			return wireType{}, fmt.Errorf("unsupported number wire type %q", node.UnderlyingType)
		}
	case "integer":
		return integerWire(node.UnderlyingType, node.SerializationOptions)
	default:
		return wireType{}, fmt.Errorf("unsupported schema type %q", node.Type)
	}
}

func isEnumAsValue(node rawNode) bool {
	return node.Type == "string" && node.UnderlyingType != "" && hasOption(node.SerializationOptions, "Enum-as-Value")
}

func controlWire(typ string) (wireType, error) {
	switch typ {
	case "", "uint32":
		return wireVaruint32, nil
	case "uint8":
		return wireUint8, nil
	case "int32":
		return wireVarint32, nil
	default:
		return wireType{}, fmt.Errorf("unsupported oneOf control type %q", typ)
	}
}

func integerWire(typ string, options []string) (wireType, error) {
	compressed := hasOption(options, "Compression")
	bigEndian := hasOption(options, "Big Endian")
	switch typ {
	case "uint8":
		return wireUint8, nil
	case "int8":
		return wireInt8, nil
	case "uint16":
		return wireUint16, nil
	case "int16":
		return wireInt16, nil
	case "uint32":
		if compressed {
			return wireVaruint32, nil
		}
		return wireUint32, nil
	case "", "int32":
		if compressed {
			return wireVarint32, nil
		}
		if bigEndian {
			return wireBEInt32, nil
		}
		return wireInt32, nil
	case "uint64":
		if compressed {
			return wireVaruint64, nil
		}
		return wireUint64, nil
	case "int64":
		if compressed {
			return wireVarint64, nil
		}
		return wireInt64, nil
	default:
		return wireType{}, fmt.Errorf("unsupported integer wire type %q", typ)
	}
}

func hasOption(options []string, option string) bool {
	return slices.ContainsFunc(options, func(s string) bool {
		return strings.EqualFold(s, option)
	})
}

func readControl(io protocol.IO, wire wireType) uint32 {
	switch v := wire.decode(io).(type) {
	case int32:
		return uint32(v)
	case int64:
		return uint32(v)
	default:
		return uint32(asUint64(v))
	}
}

func decodeEnum(io protocol.IO, name string, enum []string, value any) any {
	index := asUint64(value)
	if index >= uint64(len(enum)) {
		io.InvalidValue(index, name, "unknown enum ordinal")
		return value
	}
	return enum[index]
}

func encodeEnumValue(io protocol.IO, fieldName string, enum []string, value any) any {
	name, ok := value.(string)
	if !ok {
		return value
	}
	index := slices.Index(enum, name)
	if index < 0 {
		io.InvalidValue(name, fieldName, "unknown enum value")
		return value
	}
	return uint64(index)
}

func variantByIndex(variants []variantSpec, index uint32) (variantSpec, bool) {
	for _, variant := range variants {
		if variant.index == index {
			return variant, true
		}
	}
	return variantSpec{}, false
}

func asVariant(io protocol.IO, fieldName string, variants []variantSpec, value any) (Variant, bool) {
	switch v := value.(type) {
	case Variant:
		return v, true
	case *Variant:
		if v == nil {
			io.InvalidValue(value, fieldName, "oneOf value must be a Variant or map matching exactly one variant")
			return Variant{}, false
		}
		return *v, true
	case map[string]any:
		var matched variantSpec
		matches := 0
		for _, variant := range variants {
			if variantFieldsMatch(variant.fields, v) {
				matched = variant
				matches++
			}
		}
		if matches == 1 {
			return Variant{Index: matched.index, Title: matched.title, Value: v}, true
		}
		io.InvalidValue(value, fieldName, "oneOf map value must match exactly one variant")
		return Variant{}, false
	default:
		io.InvalidValue(value, fieldName, "oneOf value must be a Variant or map matching exactly one variant")
		return Variant{}, false
	}
}

func variantFieldsMatch(fields []fieldSpec, values map[string]any) bool {
	if len(fields) != len(values) {
		return false
	}
	for _, field := range fields {
		if _, ok := values[field.name]; !ok {
			return false
		}
	}
	return true
}

func asMap(value any) map[string]any {
	if v, ok := value.(map[string]any); ok {
		return v
	}
	return map[string]any{}
}

func asSlice(value any) []any {
	if v, ok := value.([]any); ok {
		return v
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		values := make([]any, v.Len())
		for i := range values {
			values[i] = v.Index(i).Interface()
		}
		return values
	default:
		return nil
	}
}

func asString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return ""
	}
}

func asBool(value any) bool {
	v, _ := value.(bool)
	return v
}

func asFloat64(value any) float64 {
	switch v := value.(type) {
	case json.Number:
		f, _ := v.Float64()
		return f
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Float32, reflect.Float64:
		return v.Float()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return float64(v.Uint())
	default:
		return 0
	}
}

func asInt64(value any) int64 {
	switch v := value.(type) {
	case json.Number:
		i, _ := v.Int64()
		return i
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if v.Uint() > math.MaxInt64 {
			return 0
		}
		return int64(v.Uint())
	default:
		return 0
	}
}

func asUint64(value any) uint64 {
	switch v := value.(type) {
	case json.Number:
		i, err := v.Int64()
		if err == nil && i >= 0 {
			return uint64(i)
		}
		return 0
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if v.Int() < 0 {
			return 0
		}
		return uint64(v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint()
	default:
		return 0
	}
}

func toUint32(value any) (uint32, error) {
	id := asUint64(value)
	if id > math.MaxUint32 {
		return 0, fmt.Errorf("packet ID %d overflows uint32", id)
	}
	return uint32(id), nil
}
