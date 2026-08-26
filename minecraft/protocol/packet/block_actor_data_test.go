package packet

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/nbt"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

func TestBlockActorData_RawNBTRoundTrip(t *testing.T) {
	t.Parallel()

	wantData := map[string]any{
		"id":         "Chest",
		"pairx":      int32(2),
		"pairz":      int32(3),
		"CustomName": "loot",
	}
	wantRaw, err := nbt.MarshalEncoding(wantData, nbt.NetworkLittleEndian)
	if err != nil {
		t.Fatal(err)
	}
	want := &BlockActorData{Position: protocol.BlockPos{1, 64, 1}, RawNBT: wantRaw}
	buf := new(bytes.Buffer)
	translation := protocol.ActorIDTranslation{}
	want.Marshal(translation.WrapWriter(protocol.NewWriter(buf, 0)))

	got := new(BlockActorData)
	got.Marshal(translation.WrapReader(protocol.NewReader(buf, 0, true)))
	if got.Position != want.Position {
		t.Fatalf("Position = %v, want %v", got.Position, want.Position)
	}
	if got.NBTData != nil {
		t.Fatalf("NBTData = %#v, want nil lazy data", got.NBTData)
	}
	if !bytes.Equal(got.RawNBT, wantRaw) {
		t.Fatalf("RawNBT changed:\n%x\n%x", got.RawNBT, wantRaw)
	}

	filtered, err := got.FilterNBT(func(key string) bool { return key == "pairx" || key == "pairz" })
	if err != nil {
		t.Fatalf("FilterNBT() error = %v", err)
	}
	wantFiltered := map[string]any{"pairx": int32(2), "pairz": int32(3)}
	if !reflect.DeepEqual(filtered, wantFiltered) {
		t.Fatalf("FilterNBT() = %#v, want %#v", filtered, wantFiltered)
	}

	forwarded := new(bytes.Buffer)
	got.Marshal(protocol.NewWriter(forwarded, 0))
	if !bytes.Equal(forwarded.Bytes(), appendPosition(want.Position, wantRaw)) {
		t.Fatal("forwarding did not preserve the exact packet payload")
	}
}

func TestBlockActorData_MapFallback(t *testing.T) {
	t.Parallel()

	pk := &BlockActorData{NBTData: map[string]any{"pairx": int32(2), "CustomName": "loot"}}
	filtered, err := pk.FilterNBT(func(key string) bool { return key == "pairx" })
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]any{"pairx": int32(2)}; !reflect.DeepEqual(filtered, want) {
		t.Fatalf("FilterNBT() = %#v, want %#v", filtered, want)
	}

	buf := new(bytes.Buffer)
	pk.Marshal(protocol.NewWriter(buf, 0))
	decoded := new(BlockActorData)
	decoded.Marshal(protocol.NewReader(buf, 0, true))
	var got map[string]any
	if err := nbt.UnmarshalEncoding(decoded.RawNBT, &got, nbt.NetworkLittleEndian); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, pk.NBTData) {
		t.Fatalf("decoded NBT = %#v, want %#v", got, pk.NBTData)
	}
}

func appendPosition(pos protocol.BlockPos, raw []byte) []byte {
	buf := new(bytes.Buffer)
	protocol.NewWriter(buf, 0).BlockPos(&pos)
	return append(buf.Bytes(), raw...)
}
