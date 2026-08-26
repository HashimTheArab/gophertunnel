package nbt

import (
	"bytes"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestUnmarshalNetworkFiltered_SelectedRootEntries(t *testing.T) {
	t.Parallel()

	input := map[string]any{
		"pairx": int32(12),
		"pairz": int32(-4),
		"Patterns": []any{
			map[string]any{"Pattern": "bri", "Color": int32(1)},
		},
		"Items": []any{
			map[string]any{"Name": "minecraft:diamond", "tag": map[string]any{"display": strings.Repeat("x", 4096)}},
		},
	}
	raw, err := MarshalEncoding(input, NetworkLittleEndian)
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	err = UnmarshalNetworkFiltered(raw, &got, func(key string) bool {
		return key == "pairx" || key == "Patterns"
	})
	if err != nil {
		t.Fatalf("UnmarshalNetworkFiltered() error = %v", err)
	}
	want := map[string]any{
		"pairx": int32(12),
		"Patterns": []any{
			map[string]any{"Pattern": "bri", "Color": int32(1)},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UnmarshalNetworkFiltered() = %#v, want %#v", got, want)
	}
}

func TestValidateNetwork_RejectsMalformedOrTrailingData(t *testing.T) {
	t.Parallel()

	raw, err := MarshalEncoding(map[string]any{"id": "Chest"}, NetworkLittleEndian)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateNetwork(raw); err != nil {
		t.Fatalf("ValidateNetwork() error = %v", err)
	}
	for name, malformed := range map[string][]byte{
		"truncated": raw[:len(raw)-1],
		"trailing":  append(append([]byte(nil), raw...), 0xff),
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateNetwork(malformed); err == nil {
				t.Fatal("ValidateNetwork() error = nil")
			}
		})
	}
}

func TestDecoderDecodeFiltered_RejectsTruncatedReaderWithoutNext(t *testing.T) {
	t.Parallel()

	raw, err := MarshalEncoding(map[string]any{"payload": strings.Repeat("x", 64)}, NetworkLittleEndian)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDecoder(io.LimitReader(bytes.NewReader(raw), int64(len(raw)-1)))
	if err := d.DecodeFiltered(nil, nil); err == nil {
		t.Fatal("DecodeFiltered() error = nil")
	}
}

func BenchmarkUnmarshalNetworkValidatedFiltered(b *testing.B) {
	input := map[string]any{
		"pairx": int32(12),
		"pairz": int32(-4),
		"Items": []any{
			map[string]any{"Name": "minecraft:diamond", "tag": map[string]any{"display": strings.Repeat("x", 4096)}},
		},
	}
	raw, err := MarshalEncoding(input, NetworkLittleEndian)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for range b.N {
		if err := ValidateNetwork(raw); err != nil {
			b.Fatal(err)
		}
		var got map[string]any
		if err := UnmarshalNetworkFiltered(raw, &got, func(key string) bool { return key == "pairx" || key == "pairz" }); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnmarshalNetworkEager(b *testing.B) {
	input := map[string]any{
		"pairx": int32(12),
		"pairz": int32(-4),
		"Items": []any{
			map[string]any{"Name": "minecraft:diamond", "tag": map[string]any{"display": strings.Repeat("x", 4096)}},
		},
	}
	raw, err := MarshalEncoding(input, NetworkLittleEndian)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for range b.N {
		var got map[string]any
		if err := UnmarshalEncoding(raw, &got, NetworkLittleEndian); err != nil {
			b.Fatal(err)
		}
	}
}
