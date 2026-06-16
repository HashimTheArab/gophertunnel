package runtimeprotocol

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
)

type schemaDocument struct {
	Title           string             `json:"title"`
	MinecraftVer    string             `json:"x-minecraft-version"`
	ProtocolVersion int32              `json:"x-protocol-version"`
	Definitions     map[string]rawNode `json:"definitions"`
	Properties      map[string]rawNode `json:"properties"`
	Meta            map[string]any     `json:"$metaProperties"`
}

type rawNode struct {
	Ref                  string             `json:"$ref"`
	Title                string             `json:"title"`
	Type                 string             `json:"type"`
	Enum                 []string           `json:"enum"`
	Properties           map[string]rawNode `json:"properties"`
	Items                *rawNode           `json:"items"`
	OneOf                []rawNode          `json:"oneOf"`
	UnderlyingType       string             `json:"x-underlying-type"`
	ControlValueType     string             `json:"x-control-value-type"`
	SerializationOptions []string           `json:"x-serialization-options"`
	Ordinal              *int               `json:"x-ordinal-index"`
}

type packetSpec struct {
	id     uint32
	title  string
	fields []fieldSpec
}

func (s *packetSpec) decode(io interfaceIO) map[string]any {
	values := make(map[string]any, len(s.fields))
	decodeFields(io, s.fields, values)
	return values
}

func (s *packetSpec) encode(io interfaceIO, values map[string]any) {
	encodeFields(io, s.fields, values)
}

type interfaceIO = interface {
	Uint16(*uint16)
	Int16(*int16)
	Uint32(*uint32)
	Int32(*int32)
	BEInt32(*int32)
	Uint64(*uint64)
	Int64(*int64)
	Float32(*float32)
	Float64(*float64)
	Uint8(*uint8)
	Int8(*int8)
	Bool(*bool)
	Varint64(*int64)
	Varuint64(*uint64)
	Varint32(*int32)
	Varuint32(*uint32)
	String(*string)
	InvalidValue(any, string, string)
}

type fieldKind uint8

const (
	fieldScalar fieldKind = iota
	fieldObject
	fieldArray
	fieldVariant
)

type fieldSpec struct {
	name     string
	kind     fieldKind
	wire     wireType
	enum     []string
	fields   []fieldSpec
	elem     *fieldSpec
	variants []variantSpec
}

type variantSpec struct {
	index  uint32
	title  string
	fields []fieldSpec
}

type compiler struct {
	doc *schemaDocument
}

func loadSchemas(fsys fs.FS, protocolID int32, cfg loadConfig) (*Protocol, error) {
	p := &Protocol{
		id:       protocolID,
		fallback: cfg.fallback,
		packets:  map[uint32]*packetSpec{},
	}
	if p.fallback == nil {
		return nil, fmt.Errorf("runtime protocol: fallback protocol is nil")
	}

	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || strings.ToLower(path.Ext(name)) != ".json" {
			return nil
		}
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return err
		}
		var doc schemaDocument
		dec := json.NewDecoder(strings.NewReader(string(data)))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			return fmt.Errorf("decode %s: %w", name, err)
		}
		if doc.ProtocolVersion != protocolID {
			return nil
		}
		id, ok, err := schemaPacketID(doc.Meta)
		if err != nil {
			return fmt.Errorf("packet ID in %s: %w", name, err)
		}
		if !ok {
			return nil
		}
		spec, err := (&compiler{doc: &doc}).compilePacket(id)
		if err != nil {
			return fmt.Errorf("compile %s: %w", name, err)
		}
		p.packets[id] = spec
		if p.version == "" {
			p.version = doc.MinecraftVer
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if p.version == "" {
		p.version = p.fallback.Ver()
	}
	return p, nil
}

func schemaPacketID(meta map[string]any) (uint32, bool, error) {
	if meta == nil {
		return 0, false, nil
	}
	value, ok := meta["[cereal:packet]"]
	if !ok {
		return 0, false, nil
	}
	id, err := toUint32(value)
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}

func (c *compiler) compilePacket(id uint32) (*packetSpec, error) {
	fields, err := c.compileProperties(c.doc.Properties)
	if err != nil {
		return nil, err
	}
	return &packetSpec{id: id, title: c.doc.Title, fields: fields}, nil
}

func (c *compiler) compileProperties(properties map[string]rawNode) ([]fieldSpec, error) {
	names := make([]string, 0, len(properties))
	for name := range properties {
		names = append(names, name)
	}
	slices.SortFunc(names, func(a, b string) int {
		return ordinal(properties[a]) - ordinal(properties[b])
	})

	fields := make([]fieldSpec, 0, len(names))
	for _, name := range names {
		field, err := c.compileField(name, properties[name])
		if err != nil {
			return nil, err
		}
		fields = append(fields, field)
	}
	return fields, nil
}

func (c *compiler) compileField(name string, node rawNode) (fieldSpec, error) {
	if node.Ref != "" && len(node.OneOf) == 0 {
		resolved, err := c.resolve(node.Ref)
		if err != nil {
			return fieldSpec{}, err
		}
		node = mergeNode(resolved, node)
	}
	if len(node.OneOf) != 0 {
		wire, err := controlWire(node.ControlValueType)
		if err != nil {
			return fieldSpec{}, fmt.Errorf("%s: %w", name, err)
		}
		variants := make([]variantSpec, 0, len(node.OneOf))
		for i, rawVariant := range node.OneOf {
			index := uint32(i)
			if rawVariant.Ordinal != nil {
				index = uint32(*rawVariant.Ordinal)
			}
			resolved := rawVariant
			if rawVariant.Ref != "" {
				var err error
				resolved, err = c.resolve(rawVariant.Ref)
				if err != nil {
					return fieldSpec{}, err
				}
			}
			fields, err := c.compileProperties(resolved.Properties)
			if err != nil {
				return fieldSpec{}, err
			}
			variants = append(variants, variantSpec{index: index, title: resolved.Title, fields: fields})
		}
		return fieldSpec{name: name, kind: fieldVariant, wire: wire, variants: variants}, nil
	}
	if len(node.Properties) != 0 || node.Type == "object" {
		fields, err := c.compileProperties(node.Properties)
		if err != nil {
			return fieldSpec{}, err
		}
		return fieldSpec{name: name, kind: fieldObject, fields: fields}, nil
	}
	if node.Type == "array" {
		if node.Items == nil {
			return fieldSpec{}, fmt.Errorf("%s: array schema missing items", name)
		}
		elem, err := c.compileField("", *node.Items)
		if err != nil {
			return fieldSpec{}, err
		}
		return fieldSpec{name: name, kind: fieldArray, elem: &elem}, nil
	}
	wire, err := scalarWire(node)
	if err != nil {
		return fieldSpec{}, fmt.Errorf("%s: %w", name, err)
	}
	var enum []string
	if isEnumAsValue(node) {
		enum = node.Enum
	}
	return fieldSpec{name: name, kind: fieldScalar, wire: wire, enum: enum}, nil
}

func (c *compiler) resolve(ref string) (rawNode, error) {
	const prefix = "#/definitions/"
	if !strings.HasPrefix(ref, prefix) {
		return rawNode{}, fmt.Errorf("unsupported ref %q", ref)
	}
	key := strings.TrimPrefix(ref, prefix)
	node, ok := c.doc.Definitions[key]
	if !ok {
		return rawNode{}, fmt.Errorf("unknown ref %q", ref)
	}
	return node, nil
}

func mergeNode(base, overlay rawNode) rawNode {
	base.Ordinal = overlay.Ordinal
	return base
}

func ordinal(node rawNode) int {
	if node.Ordinal == nil {
		return int(^uint(0) >> 1)
	}
	return *node.Ordinal
}
