package runtimeprotocol_test

import (
	"bytes"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"github.com/sandertv/gophertunnel/minecraft/protocol/runtimeprotocol"
)

func TestLoadMojangJSONOverlaysFallbackPool(t *testing.T) {
	proto, err := runtimeprotocol.LoadMojangJSON(schemaFS(map[string]string{
		"TextPacket.json": `{
			"x-minecraft-version": "1.26.30",
			"x-protocol-version": 1001,
			"title": "TextPacket",
			"type": "object",
			"properties": {
				"Message": {"type": "string", "x-ordinal-index": 0}
			},
			"$metaProperties": {"[cereal:packet]": 9}
		}`,
	}), 1001, runtimeprotocol.WithFallback(minecraft.DefaultProtocol))
	if err != nil {
		t.Fatalf("LoadMojangJSON: %v", err)
	}
	if proto.ID() != 1001 {
		t.Fatalf("protocol ID = %v, want 1001", proto.ID())
	}
	if proto.Ver() != "1.26.30" {
		t.Fatalf("protocol version = %q, want 1.26.30", proto.Ver())
	}

	pk := proto.Packets(true)[packet.IDText]()
	dynamic, ok := pk.(*runtimeprotocol.DynamicPacket)
	if !ok {
		t.Fatalf("packet type = %T, want *runtimeprotocol.DynamicPacket", pk)
	}

	in := bytes.NewBuffer([]byte{5, 'h', 'e', 'l', 'l', 'o'})
	dynamic.Marshal(proto.NewReader(in, 0, true))
	if got := dynamic.Values["Message"]; got != "hello" {
		t.Fatalf("decoded Message = %#v, want hello", got)
	}

	dynamic.Values = map[string]any{"Message": "hello"}
	var out bytes.Buffer
	dynamic.Marshal(proto.NewWriter(&out, 0))
	if got, want := out.Bytes(), []byte{5, 'h', 'e', 'l', 'l', 'o'}; !bytes.Equal(got, want) {
		t.Fatalf("encoded payload = %x, want %x", got, want)
	}
}

func TestPacketsKeepsInternalFallbackPackets(t *testing.T) {
	proto, err := runtimeprotocol.LoadMojangJSON(schemaFS(map[string]string{
		"RequestNetworkSettingsPacket.json": `{
			"x-minecraft-version": "1.26.30",
			"x-protocol-version": 1001,
			"title": "RequestNetworkSettingsPacket",
			"description": "Sent from client to server to initiate a connection.",
			"type": "object",
			"properties": {
				"ClientNetworkVersion": {
					"type": "integer",
					"x-underlying-type": "int32",
					"x-serialization-options": ["Big Endian"],
					"x-ordinal-index": 0
				}
			},
			"$metaProperties": {"[cereal:packet]": 193}
		}`,
	}), 1001, runtimeprotocol.WithFallback(minecraft.DefaultProtocol))
	if err != nil {
		t.Fatalf("LoadMojangJSON: %v", err)
	}

	pk := proto.Packets(true)[packet.IDRequestNetworkSettings]()
	if _, ok := pk.(*packet.RequestNetworkSettings); !ok {
		t.Fatalf("listener RequestNetworkSettings packet type = %T, want *packet.RequestNetworkSettings", pk)
	}
}

func TestPacketsDoesNotMutateFallbackPool(t *testing.T) {
	pool := packet.Pool{
		packet.IDText: func() packet.Packet { return &packet.Text{} },
	}
	proto, err := runtimeprotocol.LoadMojangJSON(schemaFS(map[string]string{
		"TextPacket.json": `{
			"x-minecraft-version": "1.26.30",
			"x-protocol-version": 1001,
			"title": "TextPacket",
			"type": "object",
			"properties": {},
			"$metaProperties": {"[cereal:packet]": 9}
		}`,
	}), 1001, runtimeprotocol.WithFallback(sharedFallback{pool: pool}))
	if err != nil {
		t.Fatalf("LoadMojangJSON: %v", err)
	}

	if _, ok := proto.Packets(true)[packet.IDText]().(*runtimeprotocol.DynamicPacket); !ok {
		t.Fatalf("runtime pool Text packet was not dynamic")
	}
	if _, ok := pool[packet.IDText]().(*packet.Text); !ok {
		t.Fatalf("fallback pool Text packet was mutated")
	}
}

func TestLoadMojangJSONRejectsDuplicatePacketIDs(t *testing.T) {
	_, err := runtimeprotocol.LoadMojangJSON(schemaFS(map[string]string{
		"TextPacket.json": `{
			"x-minecraft-version": "1.26.30",
			"x-protocol-version": 1001,
			"title": "TextPacket",
			"type": "object",
			"properties": {},
			"$metaProperties": {"[cereal:packet]": 9}
		}`,
		"TextPacketDuplicate.json": `{
			"x-minecraft-version": "1.26.30",
			"x-protocol-version": 1001,
			"title": "TextPacketDuplicate",
			"type": "object",
			"properties": {},
			"$metaProperties": {"[cereal:packet]": 9}
		}`,
	}), 1001, runtimeprotocol.WithFallback(minecraft.DefaultProtocol))
	if err == nil {
		t.Fatalf("LoadMojangJSON succeeded with duplicate packet IDs")
	}
}

func TestLoadMojangJSONRejectsUnsupportedCompressedInteger(t *testing.T) {
	_, err := runtimeprotocol.LoadMojangJSON(schemaFS(map[string]string{
		"TextPacket.json": `{
			"x-minecraft-version": "1.26.30",
			"x-protocol-version": 1001,
			"title": "TextPacket",
			"type": "object",
			"properties": {
				"Message Type": {
					"type": "integer",
					"x-underlying-type": "uint8",
					"x-serialization-options": ["Compression"],
					"x-ordinal-index": 0
				}
			},
			"$metaProperties": {"[cereal:packet]": 9}
		}`,
	}), 1001, runtimeprotocol.WithFallback(minecraft.DefaultProtocol))
	if err == nil {
		t.Fatalf("LoadMojangJSON succeeded with unsupported compressed integer")
	}
}

func TestDynamicPacketOrdersEqualOrdinalsByFieldName(t *testing.T) {
	proto, err := runtimeprotocol.LoadMojangJSON(schemaFS(map[string]string{
		"TextPacket.json": `{
			"x-minecraft-version": "1.26.30",
			"x-protocol-version": 1001,
			"title": "TextPacket",
			"description": "Sent from server to client.",
			"type": "object",
			"properties": {
				"B": {"type": "string", "x-ordinal-index": 0},
				"A": {"type": "string", "x-ordinal-index": 0}
			},
			"$metaProperties": {"[cereal:packet]": 9}
		}`,
	}), 1001, runtimeprotocol.WithFallback(minecraft.DefaultProtocol))
	if err != nil {
		t.Fatalf("LoadMojangJSON: %v", err)
	}

	pk := proto.Packets(false)[packet.IDText]().(*runtimeprotocol.DynamicPacket)
	pk.Values = map[string]any{"A": "first", "B": "second"}
	var out bytes.Buffer
	pk.Marshal(proto.NewWriter(&out, 0))

	var want bytes.Buffer
	writeString(&want, "first")
	writeString(&want, "second")
	if !bytes.Equal(out.Bytes(), want.Bytes()) {
		t.Fatalf("encoded payload = %x, want %x", out.Bytes(), want.Bytes())
	}
}

func TestDynamicPacketHandlesOneOfVariants(t *testing.T) {
	proto, err := runtimeprotocol.LoadMojangJSON(schemaFS(map[string]string{
		"TextPacket.json": `{
			"x-minecraft-version": "1.26.30",
			"x-protocol-version": 1001,
			"title": "TextPacket",
			"type": "object",
			"definitions": {
				"message_only": {
					"title": "MessageOnly",
					"type": "object",
					"properties": {
						"Message Type": {
							"type": "string",
							"enum": ["raw", "tip"],
							"x-underlying-type": "uint8",
							"x-serialization-options": ["Enum-as-Value"],
							"x-ordinal-index": 0
						},
						"Message": {"type": "string", "x-ordinal-index": 1}
					}
				},
				"authored": {
					"title": "AuthorAndMessage",
					"type": "object",
					"properties": {
						"Author": {"type": "string", "x-ordinal-index": 0},
						"Message": {"type": "string", "x-ordinal-index": 1}
					}
				}
			},
			"properties": {
				"Localize?": {
					"type": "boolean",
					"x-underlying-type": "boolean",
					"x-ordinal-index": 0
				},
				"Body": {
					"oneOf": [
						{"$ref": "#/definitions/message_only", "x-ordinal-index": 0},
						{"$ref": "#/definitions/authored", "x-ordinal-index": 1}
					],
					"x-control-value-type": "uint8",
					"x-ordinal-index": 1
				}
			},
			"$metaProperties": {"[cereal:packet]": 9}
		}`,
	}), 1001, runtimeprotocol.WithFallback(minecraft.DefaultProtocol))
	if err != nil {
		t.Fatalf("LoadMojangJSON: %v", err)
	}

	pk := proto.Packets(false)[packet.IDText]().(*runtimeprotocol.DynamicPacket)
	pk.Values = map[string]any{
		"Localize?": false,
		"Body": runtimeprotocol.Variant{
			Index: 0,
			Value: map[string]any{
				"Message Type": "raw",
				"Message":      "hello",
			},
		},
	}
	var out bytes.Buffer
	pk.Marshal(proto.NewWriter(&out, 0))

	var want bytes.Buffer
	_ = want.WriteByte(0)
	_ = want.WriteByte(0)
	_ = want.WriteByte(0)
	writeString(&want, "hello")
	if !bytes.Equal(out.Bytes(), want.Bytes()) {
		t.Fatalf("encoded payload = %x, want %x", out.Bytes(), want.Bytes())
	}

	decoded := proto.Packets(false)[packet.IDText]().(*runtimeprotocol.DynamicPacket)
	decoded.Marshal(proto.NewReader(bytes.NewBuffer(out.Bytes()), 0, true))
	if got := decoded.Values["Localize?"]; got != false {
		t.Fatalf("decoded Localize? = %#v, want false", got)
	}
	body, ok := decoded.Values["Body"].(runtimeprotocol.Variant)
	if !ok {
		t.Fatalf("decoded Body type = %T, want runtimeprotocol.Variant", decoded.Values["Body"])
	}
	if body.Index != 0 {
		t.Fatalf("decoded Body index = %v, want 0", body.Index)
	}
	if got := body.Value["Message"]; got != "hello" {
		t.Fatalf("decoded Body.Message = %#v, want hello", got)
	}
	if got := body.Value["Message Type"]; got != "raw" {
		t.Fatalf("decoded Body.Message Type = %#v, want raw", got)
	}

	pk.Values = map[string]any{
		"Localize?": false,
		"Body": map[string]any{
			"Author":  "Steve",
			"Message": "hello",
		},
	}
	out.Reset()
	pk.Marshal(proto.NewWriter(&out, 0))
	if got := out.Bytes()[1]; got != 1 {
		t.Fatalf("encoded bare map Body index = %v, want 1", got)
	}
}

func TestDynamicPacketRejectsInvalidOneOfValue(t *testing.T) {
	proto, err := runtimeprotocol.LoadMojangJSON(schemaFS(map[string]string{
		"TextPacket.json": `{
			"x-minecraft-version": "1.26.30",
			"x-protocol-version": 1001,
			"title": "TextPacket",
			"type": "object",
			"definitions": {
				"message_only": {
					"title": "MessageOnly",
					"type": "object",
					"properties": {
						"Message": {"type": "string", "x-ordinal-index": 0}
					}
				}
			},
			"properties": {
				"Body": {
					"oneOf": [
						{"$ref": "#/definitions/message_only", "x-ordinal-index": 0}
					],
					"x-control-value-type": "uint8",
					"x-ordinal-index": 0
				}
			},
			"$metaProperties": {"[cereal:packet]": 9}
		}`,
	}), 1001, runtimeprotocol.WithFallback(minecraft.DefaultProtocol))
	if err != nil {
		t.Fatalf("LoadMojangJSON: %v", err)
	}

	defer func() {
		if recover() == nil {
			t.Fatalf("expected invalid oneOf value to panic")
		}
	}()
	pk := proto.Packets(false)[packet.IDText]().(*runtimeprotocol.DynamicPacket)
	pk.Values = map[string]any{"Body": "not a variant"}
	var out bytes.Buffer
	pk.Marshal(proto.NewWriter(&out, 0))
}

func TestDynamicPacketRejectsInvalidObjectValue(t *testing.T) {
	proto, err := runtimeprotocol.LoadMojangJSON(schemaFS(map[string]string{
		"TextPacket.json": `{
			"x-minecraft-version": "1.26.30",
			"x-protocol-version": 1001,
			"title": "TextPacket",
			"description": "Sent from server to client.",
			"type": "object",
			"properties": {
				"Body": {
					"type": "object",
					"properties": {
						"Message": {"type": "string", "x-ordinal-index": 0}
					},
					"x-ordinal-index": 0
				}
			},
			"$metaProperties": {"[cereal:packet]": 9}
		}`,
	}), 1001, runtimeprotocol.WithFallback(minecraft.DefaultProtocol))
	if err != nil {
		t.Fatalf("LoadMojangJSON: %v", err)
	}

	defer func() {
		if recover() == nil {
			t.Fatalf("expected invalid object value to panic")
		}
	}()
	pk := proto.Packets(false)[packet.IDText]().(*runtimeprotocol.DynamicPacket)
	pk.Values = map[string]any{"Body": "not an object"}
	var out bytes.Buffer
	pk.Marshal(proto.NewWriter(&out, 0))
}

func TestLoadMojangJSONRespectsPacketDirection(t *testing.T) {
	proto, err := runtimeprotocol.LoadMojangJSON(schemaFS(map[string]string{
		"CommandRequestPacket.json": `{
			"x-minecraft-version": "1.26.30",
			"x-protocol-version": 1001,
			"title": "CommandRequestPacket",
			"description": "Sent from client to server.",
			"type": "object",
			"properties": {},
			"$metaProperties": {"[cereal:packet]": 77}
		}`,
		"SetTimePacket.json": `{
			"x-minecraft-version": "1.26.30",
			"x-protocol-version": 1001,
			"title": "SetTimePacket",
			"description": "Sent from the server to client.",
			"type": "object",
			"properties": {},
			"$metaProperties": {"[cereal:packet]": 10}
		}`,
	}), 1001, runtimeprotocol.WithFallback(minecraft.DefaultProtocol))
	if err != nil {
		t.Fatalf("LoadMojangJSON: %v", err)
	}

	if _, ok := proto.Packets(true)[packet.IDCommandRequest]().(*runtimeprotocol.DynamicPacket); !ok {
		t.Fatalf("listener CommandRequest packet was not dynamic")
	}
	if pkFunc, ok := proto.Packets(false)[packet.IDCommandRequest]; ok {
		if _, ok := pkFunc().(*runtimeprotocol.DynamicPacket); ok {
			t.Fatalf("dial CommandRequest packet should not be overlaid as dynamic")
		}
	}
	if _, ok := proto.Packets(false)[packet.IDSetTime]().(*runtimeprotocol.DynamicPacket); !ok {
		t.Fatalf("dial SetTime packet was not dynamic")
	}
	if pkFunc, ok := proto.Packets(true)[packet.IDSetTime]; ok {
		if _, ok := pkFunc().(*runtimeprotocol.DynamicPacket); ok {
			t.Fatalf("listener SetTime packet should not be overlaid as dynamic")
		}
	}
}

func TestLoadMojangJSONIgnoresDirectionSubstringFalsePositives(t *testing.T) {
	proto, err := runtimeprotocol.LoadMojangJSON(schemaFS(map[string]string{
		"SetTimePacket.json": `{
			"x-minecraft-version": "1.26.30",
			"x-protocol-version": 1001,
			"title": "SetTimePacket",
			"description": "Different from client clock state.",
			"type": "object",
			"properties": {},
			"$metaProperties": {"[cereal:packet]": 10}
		}`,
	}), 1001, runtimeprotocol.WithFallback(minecraft.DefaultProtocol))
	if err != nil {
		t.Fatalf("LoadMojangJSON: %v", err)
	}
	if _, ok := proto.Packets(false)[packet.IDSetTime]().(*runtimeprotocol.DynamicPacket); !ok {
		t.Fatalf("dial SetTime packet was not dynamic")
	}
	if pkFunc, ok := proto.Packets(true)[packet.IDSetTime]; ok {
		if _, ok := pkFunc().(*runtimeprotocol.DynamicPacket); ok {
			t.Fatalf("listener SetTime packet should not be overlaid as dynamic")
		}
	}
}

func TestLoadMojangJSONKeepsBidirectionalDescriptionsBidirectional(t *testing.T) {
	proto, err := runtimeprotocol.LoadMojangJSON(schemaFS(map[string]string{
		"TextPacket.json": `{
			"x-minecraft-version": "1.26.30",
			"x-protocol-version": 1001,
			"title": "TextPacket",
			"description": "Sent client to server and server to client.",
			"type": "object",
			"properties": {},
			"$metaProperties": {"[cereal:packet]": 9}
		}`,
	}), 1001, runtimeprotocol.WithFallback(minecraft.DefaultProtocol))
	if err != nil {
		t.Fatalf("LoadMojangJSON: %v", err)
	}
	if _, ok := proto.Packets(true)[packet.IDText]().(*runtimeprotocol.DynamicPacket); !ok {
		t.Fatalf("listener Text packet was not dynamic")
	}
	if _, ok := proto.Packets(false)[packet.IDText]().(*runtimeprotocol.DynamicPacket); !ok {
		t.Fatalf("dial Text packet was not dynamic")
	}
}

func TestLoadMojangJSONHandlesChainedRefsAndFloatSpelling(t *testing.T) {
	proto, err := runtimeprotocol.LoadMojangJSON(schemaFS(map[string]string{
		"TextPacket.json": `{
			"x-minecraft-version": "1.26.30",
			"x-protocol-version": 1001,
			"title": "TextPacket",
			"description": "Sent from server to client.",
			"type": "object",
			"definitions": {
				"alias": {"$ref": "#/definitions/body"},
				"body": {
					"type": "object",
					"properties": {
						"Scalar": {"type": "number", "x-underlying-type": "float", "x-ordinal-index": 0}
					}
				}
			},
			"properties": {
				"Body": {"$ref": "#/definitions/alias", "x-ordinal-index": 0}
			},
			"$metaProperties": {"[cereal:packet]": 9}
		}`,
	}), 1001, runtimeprotocol.WithFallback(minecraft.DefaultProtocol))
	if err != nil {
		t.Fatalf("LoadMojangJSON: %v", err)
	}

	pk := proto.Packets(false)[packet.IDText]().(*runtimeprotocol.DynamicPacket)
	pk.Values = map[string]any{"Body": map[string]any{"Scalar": float32(1.25)}}
	var out bytes.Buffer
	pk.Marshal(proto.NewWriter(&out, 0))

	decoded := proto.Packets(false)[packet.IDText]().(*runtimeprotocol.DynamicPacket)
	decoded.Marshal(proto.NewReader(bytes.NewBuffer(out.Bytes()), 0, true))
	body := decoded.Values["Body"].(map[string]any)
	if got := body["Scalar"]; got != float32(1.25) {
		t.Fatalf("decoded Body.Scalar = %#v, want float32(1.25)", got)
	}
}

func TestDynamicPacketEncodesTypedArraySlices(t *testing.T) {
	proto, err := runtimeprotocol.LoadMojangJSON(schemaFS(map[string]string{
		"TextPacket.json": `{
			"x-minecraft-version": "1.26.30",
			"x-protocol-version": 1001,
			"title": "TextPacket",
			"description": "Sent from server to client.",
			"type": "object",
			"properties": {
				"Messages": {
					"type": "array",
					"items": {"type": "string"},
					"x-ordinal-index": 0
				}
			},
			"$metaProperties": {"[cereal:packet]": 9}
		}`,
	}), 1001, runtimeprotocol.WithFallback(minecraft.DefaultProtocol))
	if err != nil {
		t.Fatalf("LoadMojangJSON: %v", err)
	}

	pk := proto.Packets(false)[packet.IDText]().(*runtimeprotocol.DynamicPacket)
	pk.Values = map[string]any{"Messages": []string{"hello", "world"}}
	var out bytes.Buffer
	pk.Marshal(proto.NewWriter(&out, 0))

	decoded := proto.Packets(false)[packet.IDText]().(*runtimeprotocol.DynamicPacket)
	decoded.Marshal(proto.NewReader(bytes.NewBuffer(out.Bytes()), 0, true))
	messages, ok := decoded.Values["Messages"].([]any)
	if !ok {
		t.Fatalf("decoded Messages type = %T, want []any", decoded.Values["Messages"])
	}
	if len(messages) != 2 || messages[0] != "hello" || messages[1] != "world" {
		t.Fatalf("decoded Messages = %#v, want hello/world", messages)
	}
}

func TestDynamicPacketEncodesNumericAliases(t *testing.T) {
	proto, err := runtimeprotocol.LoadMojangJSON(schemaFS(map[string]string{
		"TextPacket.json": `{
			"x-minecraft-version": "1.26.30",
			"x-protocol-version": 1001,
			"title": "TextPacket",
			"description": "Sent from server to client.",
			"type": "object",
			"properties": {
				"Count": {"type": "integer", "x-underlying-type": "uint16", "x-ordinal-index": 0},
				"Offset": {"type": "integer", "x-underlying-type": "int32", "x-ordinal-index": 1},
				"Ratio": {"type": "number", "x-underlying-type": "float", "x-ordinal-index": 2}
			},
			"$metaProperties": {"[cereal:packet]": 9}
		}`,
	}), 1001, runtimeprotocol.WithFallback(minecraft.DefaultProtocol))
	if err != nil {
		t.Fatalf("LoadMojangJSON: %v", err)
	}

	pk := proto.Packets(false)[packet.IDText]().(*runtimeprotocol.DynamicPacket)
	pk.Values = map[string]any{
		"Count":  uint8(7),
		"Offset": int16(-3),
		"Ratio":  float64(1.5),
	}
	var out bytes.Buffer
	pk.Marshal(proto.NewWriter(&out, 0))

	decoded := proto.Packets(false)[packet.IDText]().(*runtimeprotocol.DynamicPacket)
	decoded.Marshal(proto.NewReader(bytes.NewBuffer(out.Bytes()), 0, true))
	if got := decoded.Values["Count"]; got != uint16(7) {
		t.Fatalf("decoded Count = %#v, want uint16(7)", got)
	}
	if got := decoded.Values["Offset"]; got != int32(-3) {
		t.Fatalf("decoded Offset = %#v, want int32(-3)", got)
	}
	if got := decoded.Values["Ratio"]; got != float32(1.5) {
		t.Fatalf("decoded Ratio = %#v, want float32(1.5)", got)
	}
}

func TestDynamicPacketChecksArrayLengthBeforeAllocating(t *testing.T) {
	proto, err := runtimeprotocol.LoadMojangJSON(schemaFS(map[string]string{
		"TextPacket.json": `{
			"x-minecraft-version": "1.26.30",
			"x-protocol-version": 1001,
			"title": "TextPacket",
			"description": "Sent from client to server.",
			"type": "object",
			"properties": {
				"Messages": {
					"type": "array",
					"items": {"type": "string"},
					"x-ordinal-index": 0
				}
			},
			"$metaProperties": {"[cereal:packet]": 9}
		}`,
	}), 1001, runtimeprotocol.WithFallback(minecraft.DefaultProtocol))
	if err != nil {
		t.Fatalf("LoadMojangJSON: %v", err)
	}

	defer func() {
		if recover() == nil {
			t.Fatalf("expected array length check to panic")
		}
	}()
	pk := proto.Packets(true)[packet.IDText]().(*runtimeprotocol.DynamicPacket)
	pk.Marshal(proto.NewReader(bytes.NewBuffer([]byte{0x81, 0x20}), 0, true))
}

func schemaFS(files map[string]string) fs.FS {
	out := fstest.MapFS{}
	for name, data := range files {
		out[name] = &fstest.MapFile{Data: []byte(data)}
	}
	return out
}

func writeString(buf *bytes.Buffer, s string) {
	writeVaruint32(buf, uint32(len(s)))
	_, _ = buf.WriteString(s)
}

func writeVaruint32(buf *bytes.Buffer, x uint32) {
	for x >= 0x80 {
		_ = buf.WriteByte(byte(x) | 0x80)
		x >>= 7
	}
	_ = buf.WriteByte(byte(x))
}

type sharedFallback struct {
	pool packet.Pool
}

func (s sharedFallback) ID() int32   { return minecraft.DefaultProtocol.ID() }
func (s sharedFallback) Ver() string { return minecraft.DefaultProtocol.Ver() }
func (s sharedFallback) Packets(bool) packet.Pool {
	return s.pool
}
func (s sharedFallback) NewReader(r minecraft.ByteReader, shieldID int32, enableLimits bool) protocol.IO {
	return minecraft.DefaultProtocol.NewReader(r, shieldID, enableLimits)
}
func (s sharedFallback) NewWriter(w minecraft.ByteWriter, shieldID int32) protocol.IO {
	return minecraft.DefaultProtocol.NewWriter(w, shieldID)
}
func (s sharedFallback) ConvertToLatest(pk packet.Packet, conn *minecraft.Conn) []packet.Packet {
	return minecraft.DefaultProtocol.ConvertToLatest(pk, conn)
}
func (s sharedFallback) ConvertFromLatest(pk packet.Packet, conn *minecraft.Conn) []packet.Packet {
	return minecraft.DefaultProtocol.ConvertFromLatest(pk, conn)
}
