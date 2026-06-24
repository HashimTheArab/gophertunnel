package runtimeprotocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

type schemaDocument struct {
	Title           string             `json:"title"`
	Description     string             `json:"description"`
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
	direction packetDirection
	fields    []fieldSpec
}

func (s *packetSpec) decode(io protocol.IO) map[string]any {
	values := make(map[string]any, len(s.fields))
	decodeFields(io, s.fields, values)
	return values
}

func (s *packetSpec) encode(io protocol.IO, values map[string]any) {
	encodeFields(io, s.fields, values)
}

type fieldSpec struct {
	name   string
	decode func(protocol.IO) any
	encode func(protocol.IO, any)
}

type variantSpec struct {
	index  uint32
	title  string
	fields []fieldSpec
}

type packetDirection uint8

const (
	directionClient packetDirection = 1 << iota
	directionServer
	directionBoth = directionClient | directionServer
)

func (d packetDirection) allowed(listener bool) bool {
	if listener {
		return d&directionClient != 0
	}
	return d&directionServer != 0
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
		dec := json.NewDecoder(bytes.NewReader(data))
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
		spec, err := (&compiler{doc: &doc}).compilePacket(id, p.fallback)
		if err != nil {
			return fmt.Errorf("compile %s: %w", name, err)
		}
		if _, ok := p.packets[id]; ok {
			return fmt.Errorf("duplicate packet ID %d in %s", id, name)
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

func (c *compiler) compilePacket(id uint32, fallback minecraft.Protocol) (*packetSpec, error) {
	fields, err := c.compileProperties(c.doc.Properties)
	if err != nil {
		return nil, err
	}
	return &packetSpec{direction: c.packetDirection(id, fallback), fields: fields}, nil
}

func (c *compiler) compileProperties(properties map[string]rawNode) ([]fieldSpec, error) {
	names := make([]string, 0, len(properties))
	for name := range properties {
		names = append(names, name)
	}
	slices.SortFunc(names, func(a, b string) int {
		ordinalA, ordinalB := ordinal(properties[a]), ordinal(properties[b])
		switch {
		case ordinalA < ordinalB:
			return -1
		case ordinalA > ordinalB:
			return 1
		default:
			return strings.Compare(a, b)
		}
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
		resolved, err := c.resolveNode(node)
		if err != nil {
			return fieldSpec{}, err
		}
		node = resolved
	}
	if len(node.OneOf) != 0 {
		wire, err := controlWire(node.ControlValueType)
		if err != nil {
			return fieldSpec{}, fmt.Errorf("%s: %w", name, err)
		}
		variants := make([]variantSpec, 0, len(node.OneOf))
		seenIndices := map[uint32]struct{}{}
		for i, rawVariant := range node.OneOf {
			index := uint32(i)
			if rawVariant.Ordinal != nil {
				index = uint32(*rawVariant.Ordinal)
			}
			if _, ok := seenIndices[index]; ok {
				return fieldSpec{}, fmt.Errorf("%s: duplicate oneOf variant index %d", name, index)
			}
			seenIndices[index] = struct{}{}
			resolved := rawVariant
			if rawVariant.Ref != "" {
				var err error
				resolved, err = c.resolveNode(rawVariant)
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
		return fieldSpec{
			name: name,
			decode: func(io protocol.IO) any {
				index := readControl(io, wire)
				variant, ok := variantByIndex(variants, index)
				if !ok {
					io.InvalidValue(index, name, "unknown oneOf variant index")
					return Variant{Index: index}
				}
				values := make(map[string]any, len(variant.fields))
				decodeFields(io, variant.fields, values)
				return Variant{Index: index, Title: variant.title, Value: values}
			},
			encode: func(io protocol.IO, value any) {
				variant, ok := asVariant(io, name, variants, value)
				if !ok {
					return
				}
				spec, ok := variantByIndex(variants, variant.Index)
				if !ok {
					io.InvalidValue(variant.Index, name, "unknown oneOf variant index")
					return
				}
				wire.encode(io, variant.Index)
				encodeFields(io, spec.fields, variant.Value)
			},
		}, nil
	}
	if len(node.Properties) != 0 || node.Type == "object" {
		fields, err := c.compileProperties(node.Properties)
		if err != nil {
			return fieldSpec{}, err
		}
		return fieldSpec{
			name: name,
			decode: func(io protocol.IO) any {
				values := make(map[string]any, len(fields))
				decodeFields(io, fields, values)
				return values
			},
			encode: func(io protocol.IO, value any) {
				values, ok := asMap(io, name, value)
				if !ok {
					return
				}
				encodeFields(io, fields, values)
			},
		}, nil
	}
	if node.Type == "array" {
		if node.Items == nil {
			return fieldSpec{}, fmt.Errorf("%s: array schema missing items", name)
		}
		elem, err := c.compileField("", *node.Items)
		if err != nil {
			return fieldSpec{}, err
		}
		return fieldSpec{
			name: name,
			decode: func(io protocol.IO) any {
				var values []any
				protocol.FuncSlice(io, &values, func(value *any) {
					*value = elem.decode(io)
				})
				return values
			},
			encode: func(io protocol.IO, value any) {
				values, ok := asSlice(io, name, value)
				if !ok {
					return
				}
				protocol.FuncSlice(io, &values, func(value *any) {
					elem.encode(io, *value)
				})
			},
		}, nil
	}
	wire, err := scalarWire(node)
	if err != nil {
		return fieldSpec{}, fmt.Errorf("%s: %w", name, err)
	}
	var enum []string
	if isEnumAsValue(node) {
		enum = node.Enum
	}
	return fieldSpec{
		name: name,
		decode: func(io protocol.IO) any {
			value := wire.decode(io)
			if len(enum) != 0 {
				return decodeEnum(io, name, enum, value)
			}
			return value
		},
		encode: func(io protocol.IO, value any) {
			if len(enum) != 0 {
				value = encodeEnumValue(io, name, enum, value)
			}
			wire.encode(io, value)
		},
	}, nil
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

func (c *compiler) resolveNode(node rawNode) (rawNode, error) {
	ordinal := node.Ordinal
	seen := map[string]struct{}{}
	for node.Ref != "" {
		if _, ok := seen[node.Ref]; ok {
			return rawNode{}, fmt.Errorf("cyclic ref %q", node.Ref)
		}
		seen[node.Ref] = struct{}{}

		resolved, err := c.resolve(node.Ref)
		if err != nil {
			return rawNode{}, err
		}
		node = resolved
	}
	node.Ordinal = ordinal
	return node, nil
}

func (c *compiler) packetDirection(id uint32, fallback minecraft.Protocol) packetDirection {
	text := strings.ToLower(c.doc.Title + " " + c.doc.Description)
	client := strings.Contains(text, "serverbound") ||
		strings.Contains(text, "client to server") ||
		strings.Contains(text, "client-to-server")
	server := strings.Contains(text, "clientbound") ||
		strings.Contains(text, "server to client") ||
		strings.Contains(text, "server-to-client")
	switch {
	case client && server:
		return directionBoth
	case client:
		return directionClient
	case server:
		return directionServer
	}

	var direction packetDirection
	if _, ok := fallback.Packets(true)[id]; ok {
		direction |= directionClient
	}
	if _, ok := fallback.Packets(false)[id]; ok {
		direction |= directionServer
	}
	if direction == 0 {
		return directionBoth
	}
	return direction
}

func ordinal(node rawNode) int {
	if node.Ordinal == nil {
		return int(^uint(0) >> 1)
	}
	return *node.Ordinal
}
