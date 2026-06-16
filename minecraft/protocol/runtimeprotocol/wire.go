package runtimeprotocol

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"
)

type wireType uint8

const (
	wireBool wireType = iota
	wireString
	wireUint8
	wireInt8
	wireUint16
	wireInt16
	wireUint32
	wireInt32
	wireBEInt32
	wireVaruint32
	wireVarint32
	wireUint64
	wireInt64
	wireVaruint64
	wireVarint64
	wireFloat32
	wireFloat64
)

func decodeFields(io interfaceIO, fields []fieldSpec, values map[string]any) {
	for _, field := range fields {
		values[field.name] = decodeField(io, field)
	}
}

func decodeField(io interfaceIO, field fieldSpec) any {
	switch field.kind {
	case fieldScalar:
		value := decodeScalar(io, field.wire)
		if len(field.enum) != 0 {
			return decodeEnum(io, field, value)
		}
		return value
	case fieldObject:
		values := make(map[string]any, len(field.fields))
		decodeFields(io, field.fields, values)
		return values
	case fieldArray:
		var count uint32
		io.Varuint32(&count)
		values := make([]any, count)
		for i := range values {
			values[i] = decodeField(io, *field.elem)
		}
		return values
	case fieldVariant:
		index := readControl(io, field.wire)
		variant, ok := variantByIndex(field.variants, index)
		if !ok {
			io.InvalidValue(index, field.name, "unknown oneOf variant index")
			return Variant{Index: index}
		}
		values := make(map[string]any, len(variant.fields))
		decodeFields(io, variant.fields, values)
		return Variant{Index: index, Title: variant.title, Value: values}
	default:
		io.InvalidValue(field.name, "runtime schema field", "unknown field kind")
		return nil
	}
}

func encodeFields(io interfaceIO, fields []fieldSpec, values map[string]any) {
	for _, field := range fields {
		encodeField(io, field, values[field.name])
	}
}

func encodeField(io interfaceIO, field fieldSpec, value any) {
	switch field.kind {
	case fieldScalar:
		if len(field.enum) != 0 {
			value = encodeEnumValue(io, field, value)
		}
		encodeScalar(io, field.wire, value)
	case fieldObject:
		encodeFields(io, field.fields, asMap(value))
	case fieldArray:
		values := asSlice(value)
		count := uint32(len(values))
		io.Varuint32(&count)
		for _, elem := range values {
			encodeField(io, *field.elem, elem)
		}
	case fieldVariant:
		variant := asVariant(value)
		spec, ok := variantByIndex(field.variants, variant.Index)
		if !ok {
			io.InvalidValue(variant.Index, field.name, "unknown oneOf variant index")
			return
		}
		writeControl(io, field.wire, variant.Index)
		encodeFields(io, spec.fields, variant.Value)
	default:
		io.InvalidValue(field.name, "runtime schema field", "unknown field kind")
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
		case "", "float32":
			return wireFloat32, nil
		case "float64":
			return wireFloat64, nil
		default:
			return 0, fmt.Errorf("unsupported number wire type %q", node.UnderlyingType)
		}
	case "integer":
		return integerWire(node.UnderlyingType, node.SerializationOptions)
	default:
		return 0, fmt.Errorf("unsupported schema type %q", node.Type)
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
		return 0, fmt.Errorf("unsupported oneOf control type %q", typ)
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
		return 0, fmt.Errorf("unsupported integer wire type %q", typ)
	}
}

func hasOption(options []string, option string) bool {
	return slices.ContainsFunc(options, func(s string) bool {
		return strings.EqualFold(s, option)
	})
}

func decodeScalar(io interfaceIO, wire wireType) any {
	switch wire {
	case wireBool:
		var v bool
		io.Bool(&v)
		return v
	case wireString:
		var v string
		io.String(&v)
		return v
	case wireUint8:
		var v uint8
		io.Uint8(&v)
		return v
	case wireInt8:
		var v int8
		io.Int8(&v)
		return v
	case wireUint16:
		var v uint16
		io.Uint16(&v)
		return v
	case wireInt16:
		var v int16
		io.Int16(&v)
		return v
	case wireUint32:
		var v uint32
		io.Uint32(&v)
		return v
	case wireInt32:
		var v int32
		io.Int32(&v)
		return v
	case wireBEInt32:
		var v int32
		io.BEInt32(&v)
		return v
	case wireVaruint32:
		var v uint32
		io.Varuint32(&v)
		return v
	case wireVarint32:
		var v int32
		io.Varint32(&v)
		return v
	case wireUint64:
		var v uint64
		io.Uint64(&v)
		return v
	case wireInt64:
		var v int64
		io.Int64(&v)
		return v
	case wireVaruint64:
		var v uint64
		io.Varuint64(&v)
		return v
	case wireVarint64:
		var v int64
		io.Varint64(&v)
		return v
	case wireFloat32:
		var v float32
		io.Float32(&v)
		return v
	case wireFloat64:
		var v float64
		io.Float64(&v)
		return v
	default:
		io.InvalidValue(wire, "runtime schema scalar", "unknown wire type")
		return nil
	}
}

func encodeScalar(io interfaceIO, wire wireType, value any) {
	switch wire {
	case wireBool:
		v := asBool(value)
		io.Bool(&v)
	case wireString:
		v := asString(value)
		io.String(&v)
	case wireUint8:
		v := uint8(asUint64(value))
		io.Uint8(&v)
	case wireInt8:
		v := int8(asInt64(value))
		io.Int8(&v)
	case wireUint16:
		v := uint16(asUint64(value))
		io.Uint16(&v)
	case wireInt16:
		v := int16(asInt64(value))
		io.Int16(&v)
	case wireUint32:
		v := uint32(asUint64(value))
		io.Uint32(&v)
	case wireInt32:
		v := int32(asInt64(value))
		io.Int32(&v)
	case wireBEInt32:
		v := int32(asInt64(value))
		io.BEInt32(&v)
	case wireVaruint32:
		v := uint32(asUint64(value))
		io.Varuint32(&v)
	case wireVarint32:
		v := int32(asInt64(value))
		io.Varint32(&v)
	case wireUint64:
		v := asUint64(value)
		io.Uint64(&v)
	case wireInt64:
		v := asInt64(value)
		io.Int64(&v)
	case wireVaruint64:
		v := asUint64(value)
		io.Varuint64(&v)
	case wireVarint64:
		v := asInt64(value)
		io.Varint64(&v)
	case wireFloat32:
		v := float32(asFloat64(value))
		io.Float32(&v)
	case wireFloat64:
		v := asFloat64(value)
		io.Float64(&v)
	default:
		io.InvalidValue(wire, "runtime schema scalar", "unknown wire type")
	}
}

func readControl(io interfaceIO, wire wireType) uint32 {
	switch wire {
	case wireUint8:
		var v uint8
		io.Uint8(&v)
		return uint32(v)
	case wireVaruint32:
		var v uint32
		io.Varuint32(&v)
		return v
	case wireVarint32:
		var v int32
		io.Varint32(&v)
		return uint32(v)
	default:
		return uint32(asUint64(decodeScalar(io, wire)))
	}
}

func writeControl(io interfaceIO, wire wireType, value uint32) {
	switch wire {
	case wireUint8:
		v := uint8(value)
		io.Uint8(&v)
	case wireVaruint32:
		io.Varuint32(&value)
	case wireVarint32:
		v := int32(value)
		io.Varint32(&v)
	default:
		encodeScalar(io, wire, value)
	}
}

func decodeEnum(io interfaceIO, field fieldSpec, value any) any {
	index := asUint64(value)
	if index >= uint64(len(field.enum)) {
		io.InvalidValue(index, field.name, "unknown enum ordinal")
		return value
	}
	return field.enum[index]
}

func encodeEnumValue(io interfaceIO, field fieldSpec, value any) any {
	name, ok := value.(string)
	if !ok {
		return value
	}
	index := slices.Index(field.enum, name)
	if index < 0 {
		io.InvalidValue(name, field.name, "unknown enum value")
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

func asVariant(value any) Variant {
	switch v := value.(type) {
	case Variant:
		return v
	case *Variant:
		if v == nil {
			return Variant{Value: map[string]any{}}
		}
		return *v
	case map[string]any:
		return Variant{Value: v}
	default:
		return Variant{Value: map[string]any{}}
	}
}

func asMap(value any) map[string]any {
	if v, ok := value.(map[string]any); ok {
		return v
	}
	return map[string]any{}
}

func asSlice(value any) []any {
	switch v := value.(type) {
	case []any:
		return v
	case []map[string]any:
		out := make([]any, len(v))
		for i := range v {
			out[i] = v[i]
		}
		return out
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
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int32:
		return float64(v)
	case int64:
		return float64(v)
	case uint32:
		return float64(v)
	case uint64:
		return float64(v)
	case json.Number:
		f, _ := v.Float64()
		return f
	default:
		return 0
	}
}

func asInt64(value any) int64 {
	switch v := value.(type) {
	case int:
		return int64(v)
	case int8:
		return int64(v)
	case int16:
		return int64(v)
	case int32:
		return int64(v)
	case int64:
		return v
	case uint:
		if uint64(v) > math.MaxInt64 {
			return 0
		}
		return int64(v)
	case uint8:
		return int64(v)
	case uint16:
		return int64(v)
	case uint32:
		return int64(v)
	case uint64:
		if v > math.MaxInt64 {
			return 0
		}
		return int64(v)
	case json.Number:
		i, _ := v.Int64()
		return i
	default:
		return 0
	}
}

func asUint64(value any) uint64 {
	switch v := value.(type) {
	case int:
		if v < 0 {
			return 0
		}
		return uint64(v)
	case int8:
		if v < 0 {
			return 0
		}
		return uint64(v)
	case int16:
		if v < 0 {
			return 0
		}
		return uint64(v)
	case int32:
		if v < 0 {
			return 0
		}
		return uint64(v)
	case int64:
		if v < 0 {
			return 0
		}
		return uint64(v)
	case uint:
		return uint64(v)
	case uint8:
		return uint64(v)
	case uint16:
		return uint64(v)
	case uint32:
		return uint64(v)
	case uint64:
		return v
	case json.Number:
		i, err := v.Int64()
		if err == nil && i >= 0 {
			return uint64(i)
		}
		return 0
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
