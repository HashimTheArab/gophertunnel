package protocol

import (
	"bytes"
	"reflect"
	"testing"
)

// Recipe ingredients encode as a one-entry string map, then aux and count; molang uses the "tags" key.
func TestItemDescriptorCountWireFormat(t *testing.T) {
	str := func(s string) []byte { return append([]byte{byte(len(s))}, s...) }
	wire := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	aux32767 := []byte{0xfe, 0xff, 0x03}
	tests := []struct {
		name string
		in   ItemDescriptorCount
		want []byte
	}{
		{
			name: "invalid",
			in:   ItemDescriptorCount{Descriptor: &InvalidItemDescriptor{}},
			want: wire([]byte{0}, aux32767, []byte{0}),
		},
		{
			name: "name",
			in:   ItemDescriptorCount{Descriptor: &DefaultItemDescriptor{Name: "minecraft:stone", MetadataValue: 3}, Count: 1},
			want: wire([]byte{1}, str("name"), str("minecraft:stone"), []byte{6}, []byte{2}),
		},
		{
			name: "molang",
			in:   ItemDescriptorCount{Descriptor: &MoLangItemDescriptor{Expression: "q.any_tag('minecraft:planks')"}, Count: 2},
			want: wire([]byte{1}, str("tags"), str("q.any_tag('minecraft:planks')"), aux32767, []byte{4}),
		},
		{
			name: "item tag",
			in:   ItemDescriptorCount{Descriptor: &ItemTagItemDescriptor{Tag: "minecraft:logs"}, Count: 3},
			want: wire([]byte{1}, str("item_tag"), str("minecraft:logs"), aux32767, []byte{6}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			NewWriter(buf, 0).ItemDescriptorCount(&tt.in)
			if got := buf.Bytes(); !bytes.Equal(got, tt.want) {
				t.Fatalf("encoded = %x, want %x", got, tt.want)
			}

			r := bytes.NewReader(tt.want)
			var got ItemDescriptorCount
			NewReader(r, 0, true).ItemDescriptorCount(&got)
			if !reflect.DeepEqual(got, tt.in) {
				t.Fatalf("decoded %#v, want %#v", got, tt.in)
			}
			if r.Len() != 0 {
				t.Fatalf("%d trailing bytes after decode", r.Len())
			}
		})
	}
}
