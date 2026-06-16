package runtimeprotocol_test

import (
	"bytes"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"github.com/sandertv/gophertunnel/minecraft/protocol/runtimeprotocol"
)

func TestLoadMojangJSONOverlaysFallbackPool(t *testing.T) {
	proto, err := runtimeprotocol.LoadMojangJSON(schemaFS(map[string]string{
		"RequestNetworkSettingsPacket.json": `{
			"x-minecraft-version": "1.26.30",
			"x-protocol-version": 1001,
			"title": "RequestNetworkSettingsPacket",
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
	if proto.ID() != 1001 {
		t.Fatalf("protocol ID = %v, want 1001", proto.ID())
	}
	if proto.Ver() != "1.26.30" {
		t.Fatalf("protocol version = %q, want 1.26.30", proto.Ver())
	}

	pk := proto.Packets(true)[packet.IDRequestNetworkSettings]()
	dynamic, ok := pk.(*runtimeprotocol.DynamicPacket)
	if !ok {
		t.Fatalf("packet type = %T, want *runtimeprotocol.DynamicPacket", pk)
	}

	in := bytes.NewBuffer([]byte{0, 0, 3, 233})
	dynamic.Marshal(proto.NewReader(in, 0, true))
	if got := dynamic.Values["ClientNetworkVersion"]; got != int32(1001) {
		t.Fatalf("decoded ClientNetworkVersion = %#v, want int32(1001)", got)
	}

	dynamic.Values = map[string]any{"ClientNetworkVersion": int32(1001)}
	var out bytes.Buffer
	dynamic.Marshal(proto.NewWriter(&out, 0))
	if got, want := out.Bytes(), []byte{0, 0, 3, 233}; !bytes.Equal(got, want) {
		t.Fatalf("encoded payload = %x, want %x", got, want)
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
