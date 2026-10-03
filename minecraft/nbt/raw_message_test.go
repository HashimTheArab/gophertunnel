package nbt

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"
)

func TestRawMessage_DecodeFieldsSkipsUnselectedPayloads(t *testing.T) {
	t.Parallel()

	raw := encodeRawMessageFixture(t)
	message, err := ReadRaw(bytes.NewBuffer(raw), NetworkLittleEndian, true)
	if err != nil {
		t.Fatalf("ReadRaw() error = %v", err)
	}
	if got := message.Bytes(); !bytes.Equal(got, raw) {
		t.Fatalf("ReadRaw() bytes = %x, want %x", got, raw)
	}

	got, err := message.DecodeFields(NetworkLittleEndian, "pairx", "pairz", "Patterns")
	if err != nil {
		t.Fatalf("DecodeFields() error = %v", err)
	}
	want := map[string]any{
		"pairx": int32(2),
		"pairz": int32(-3),
		"Patterns": []any{
			map[string]any{"Pattern": "bri", "Color": int32(1)},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DecodeFields() = %#v, want %#v", got, want)
	}
	if _, ok := got["Items"]; ok {
		t.Fatal("DecodeFields() retained an unselected heavy field")
	}
}

func TestRawMessage_UnmarshalMaterialisesCompleteCompound(t *testing.T) {
	t.Parallel()

	raw := encodeRawMessageFixture(t)
	message, err := ReadRaw(bytes.NewBuffer(raw), NetworkLittleEndian, true)
	if err != nil {
		t.Fatalf("ReadRaw() error = %v", err)
	}
	var got map[string]any
	if err := message.Unmarshal(&got, NetworkLittleEndian); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got["CustomName"] != "large fixture" {
		t.Fatalf("Unmarshal() CustomName = %#v, want %q", got["CustomName"], "large fixture")
	}
	if _, ok := got["Items"]; !ok {
		t.Fatal("Unmarshal() omitted the heavy Items field")
	}
}

func TestRawMessage_OwnsReadBytes(t *testing.T) {
	t.Parallel()

	raw := encodeRawMessageFixture(t)
	source := bytes.NewBuffer(bytes.Clone(raw))
	message, err := ReadRaw(source, NetworkLittleEndian, true)
	if err != nil {
		t.Fatalf("ReadRaw() error = %v", err)
	}
	source.Reset()
	_, _ = source.Write(bytes.Repeat([]byte{0xff}, len(raw)))
	if got := message.Bytes(); !bytes.Equal(got, raw) {
		t.Fatalf("message changed with source reuse: got %x, want %x", got, raw)
	}
}

func TestRawMessage_ReadsGenericByteReader(t *testing.T) {
	t.Parallel()

	raw := encodeRawMessageFixture(t)
	message, err := ReadRaw(bytes.NewReader(raw), NetworkLittleEndian, true)
	if err != nil {
		t.Fatalf("ReadRaw() error = %v", err)
	}
	if got := message.Bytes(); !bytes.Equal(got, raw) {
		t.Fatalf("generic reader message = %x, want %x", got, raw)
	}
}

func TestRawMessage_RejectsTruncatedGenericReaderPayload(t *testing.T) {
	t.Parallel()

	// TAG_ByteArray, empty root name, length four, but only two payload bytes.
	raw := []byte{byte(tagByteArray), 0x00, 0x08, 0x01, 0x02}
	if _, err := ReadRaw(bytes.NewReader(raw), NetworkLittleEndian, false); err == nil {
		t.Fatal("ReadRaw() accepted a truncated byte-array payload")
	}
}

func TestRawMessage_RejectsNestedListsPastDepthLimit(t *testing.T) {
	t.Parallel()

	raw := []byte{byte(tagStruct), 0x00, byte(tagSlice), 0x01, 'x'}
	for range maximumNestingDepth {
		raw = append(raw, byte(tagSlice), 0x02)
	}
	raw = append(raw, byte(tagByte), 0x00, byte(tagEnd))

	_, err := ReadRaw(bytes.NewReader(raw), NetworkLittleEndian, false)
	var depthErr MaximumDepthReachedError
	if !errors.As(err, &depthErr) {
		t.Fatalf("ReadRaw() error = %v, want MaximumDepthReachedError", err)
	}
}

func TestRawMessage_WriteToRejectsEmptyMessage(t *testing.T) {
	t.Parallel()

	_, err := (RawMessage{}).WriteTo(io.Discard)
	var overrun BufferOverrunError
	if !errors.As(err, &overrun) {
		t.Fatalf("WriteTo() error = %v, want BufferOverrunError", err)
	}
}

func TestRawMessage_ReadsLargeBigEndianString(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		encoding Encoding
		root     []byte
	}{
		{name: "big-endian", encoding: BigEndian, root: []byte{byte(tagStruct), 0x00, 0x00}},
		{name: "network-big-endian", encoding: NetworkBigEndian, root: []byte{byte(tagStruct)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := append([]byte{}, test.root...)
			raw = append(raw, byte(tagString), 0x00, 0x00, 0x80, 0x00)
			raw = append(raw, bytes.Repeat([]byte{'a'}, 32768)...)
			raw = append(raw, byte(tagEnd))

			message, err := ReadRaw(bytes.NewReader(raw), test.encoding, false)
			if err != nil {
				t.Fatalf("ReadRaw() error = %v", err)
			}
			if got := message.Bytes(); !bytes.Equal(got, raw) {
				t.Fatalf("ReadRaw() bytes differ: got %d bytes, want %d", len(got), len(raw))
			}
		})
	}
}

// encodeRawMessageFixture returns representative nested block-actor NBT.
func encodeRawMessageFixture(t *testing.T) []byte {
	t.Helper()

	items := make([]any, 128)
	for i := range items {
		items[i] = map[string]any{
			"Name":  "minecraft:diamond_sword",
			"Count": uint8(1),
			"tag": map[string]any{
				"display": map[string]any{"Name": "a deliberately large item name"},
				"Damage":  int32(i),
			},
		}
	}
	data := map[string]any{
		"CustomName": "large fixture",
		"Items":      items,
		"pairx":      int32(2),
		"pairz":      int32(-3),
		"Patterns": []any{
			map[string]any{"Pattern": "bri", "Color": int32(1)},
		},
	}
	var buf bytes.Buffer
	if err := NewEncoderWithEncoding(&buf, NetworkLittleEndian).Encode(data); err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
	return buf.Bytes()
}
