package protocol

import (
	"bytes"
	"reflect"
	"testing"
)

func TestItemEntrySlotCapabilities(t *testing.T) {
	boolPtr := func(value bool) *bool { return &value }
	uint8Ptr := func(value uint8) *uint8 { return &value }
	tests := []struct {
		name       string
		components map[string]any
		allow      *bool
		armor      *uint8
	}{
		{name: "absent"},
		{
			name:       "explicit false",
			components: map[string]any{"item_properties": map[string]any{"allow_off_hand": false}},
			allow:      boolPtr(false),
		},
		{name: "bool", components: map[string]any{"minecraft:allow_off_hand": true}, allow: boolPtr(true)},
		{name: "uint8", components: map[string]any{"minecraft:allow_off_hand": uint8(1)}, allow: boolPtr(true)},
		{name: "int8", components: map[string]any{"minecraft:allow_off_hand": int8(0)}, allow: boolPtr(false)},
		{name: "int32", components: map[string]any{"minecraft:allow_off_hand": int32(1)}, allow: boolPtr(true)},
		{
			name:       "component value",
			components: map[string]any{"minecraft:allow_off_hand": map[string]any{"value": int8(1)}},
			allow:      boolPtr(true),
		},
		{
			name: "namespaced precedence",
			components: map[string]any{
				"item_properties":          map[string]any{"allow_off_hand": false},
				"minecraft:allow_off_hand": map[string]any{"value": int8(1)},
			},
			allow: boolPtr(true),
		},
		{name: "malformed permission", components: map[string]any{"minecraft:allow_off_hand": "true"}},
		{name: "head", components: wearableComponents("slot.armor.head"), armor: uint8Ptr(0)},
		{name: "chest", components: wearableComponents("slot.armor.chest"), armor: uint8Ptr(1)},
		{name: "legs", components: wearableComponents("slot.armor.legs"), armor: uint8Ptr(2)},
		{name: "feet", components: wearableComponents("slot.armor.feet"), armor: uint8Ptr(3)},
		{name: "body", components: wearableComponents("slot.armor.body"), armor: uint8Ptr(4)},
		{name: "numeric head", components: wearableComponents(int32(2)), armor: uint8Ptr(0)},
		{name: "numeric body", components: wearableComponents(uint32(6)), armor: uint8Ptr(4)},
		{name: "malformed wearable", components: wearableComponents("slot.weapon.mainhand")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry := ItemEntry{}
			if test.components != nil {
				entry.Data = map[string]any{"components": test.components}
			}
			caps := entry.SlotCapabilities()
			allow, hasAllow := caps.AllowOffHand.Value()
			if hasAllow != (test.allow != nil) || test.allow != nil && allow != *test.allow {
				t.Fatalf("AllowOffHand = %v, %t; want %v", allow, hasAllow, test.allow)
			}
			armor, hasArmor := caps.ArmorSlot.Value()
			if hasArmor != (test.armor != nil) || test.armor != nil && armor != *test.armor {
				t.Fatalf("ArmorSlot = %v, %t; want %v", armor, hasArmor, test.armor)
			}
		})
	}
}

func wearableComponents(slot any) map[string]any {
	return map[string]any{"minecraft:wearable": map[string]any{"slot": slot}}
}

// The reducer key packs the input as id << 16 | aux; decoding must recover the same item.
func TestMaterialReducerInputKeyRoundTrip(t *testing.T) {
	for _, item := range []ItemType{
		{NetworkID: 1},
		{NetworkID: 5, MetadataValue: 3},
		{NetworkID: 300, MetadataValue: 0x7fff},
		{NetworkID: 0x7fff, MetadataValue: 0xffff},
		{NetworkID: -5, MetadataValue: 2},
	} {
		in := MaterialReducer{InputItem: item, Outputs: []MaterialReducerOutput{{NetworkID: 7, Count: 2}}}
		buf := new(bytes.Buffer)
		NewWriter(buf, 0).MaterialReducer(&in)

		var key int32
		NewReader(bytes.NewReader(buf.Bytes()), 0, false).Varint32(&key)
		if want := item.NetworkID<<16 | int32(item.MetadataValue); key != want {
			t.Fatalf("%+v: key = %#x, want %#x", item, key, want)
		}

		var out MaterialReducer
		NewReader(bytes.NewReader(buf.Bytes()), 0, false).MaterialReducer(&out)
		if out.InputItem != item || len(out.Outputs) != 1 || out.Outputs[0] != in.Outputs[0] {
			t.Fatalf("decoded %+v, want %+v", out, in)
		}
	}
}

func TestStackRequestItem_ItemStackPreservesEveryWireField(t *testing.T) {
	result := StackRequestItem{Identifier: "minecraft:stone", MetadataValue: 7, BlockRuntimeID: 123, Count: 4, NBTData: map[string]any{"custom": "value"}, CanBePlacedOn: []string{"minecraft:grass"}, CanBreak: []string{"minecraft:dirt"}, BlockingTick: 45}
	stack := result.ItemStack(917)
	if stack.NetworkID != 917 {
		t.Fatalf("palette network ID=%d", stack.NetworkID)
	}
	// Compare every shared descriptor field so future wire fields cannot silently
	// disappear in this conversion. Identifier is intentionally palette-resolved.
	typ, src, dst := reflect.TypeOf(result), reflect.ValueOf(result), reflect.ValueOf(stack)
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if name == "Identifier" {
			continue
		}
		got := dst.FieldByName(name)
		if !got.IsValid() || !reflect.DeepEqual(src.Field(i).Interface(), got.Interface()) {
			t.Errorf("descriptor field %s lost", name)
		}
	}
}

func TestItemStack_StackRequestItemPreservesEveryWireField(t *testing.T) {
	stack := ItemStack{ItemType: ItemType{NetworkID: 917, MetadataValue: 7}, BlockRuntimeID: 123, Count: 4, NBTData: map[string]any{"custom": "value"}, CanBePlacedOn: []string{"minecraft:grass"}, CanBreak: []string{"minecraft:dirt"}, BlockingTick: 45}
	result := stack.StackRequestItem("minecraft:stone")
	if result.Identifier != "minecraft:stone" {
		t.Fatalf("identifier=%q", result.Identifier)
	}
	if !reflect.DeepEqual(result.ItemStack(stack.NetworkID), stack) {
		t.Fatalf("round trip = %#v; want %#v", result.ItemStack(stack.NetworkID), stack)
	}
	// Every descriptor field other than the identifier must come from the stack,
	// so a new wire field cannot silently disappear in this conversion.
	typ, dst, src := reflect.TypeOf(result), reflect.ValueOf(result), reflect.ValueOf(stack)
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if name == "Identifier" {
			continue
		}
		got := src.FieldByName(name)
		if !got.IsValid() || !reflect.DeepEqual(dst.Field(i).Interface(), got.Interface()) {
			t.Errorf("stack field %s lost", name)
		}
	}
}
