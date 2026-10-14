package protocol

import (
	"bytes"
	"reflect"
	"testing"
)

// cloneTestStack carries every stack field, including an ID that an ItemInstance
// codec round trip would truncate and a non-shield BlockingTick.
func cloneTestStack() ItemStack {
	return ItemStack{
		ItemType: ItemType{NetworkID: 90001, MetadataValue: 2}, BlockRuntimeID: 17, Count: 3,
		NBTData: map[string]any{
			"Damage": int32(4), "tag": map[string]any{"Unbreakable": byte(1)},
			"Lore": []string{"original"}, "nilList": []any(nil), "emptyCompound": map[string]any{},
		},
		CanBePlacedOn: []string{"minecraft:stone"}, CanBreak: []string{"minecraft:dirt"}, BlockingTick: 99,
	}
}

func TestItemInstance_CloneDetachesStack(t *testing.T) {
	original := ItemInstance{StackNetworkID: 7, Stack: cloneTestStack()}
	cloned := original.Clone()
	if !reflect.DeepEqual(cloned, original) {
		t.Fatalf("clone changed stack values: got=%#v want=%#v", cloned, original)
	}
	original.Stack.NBTData["Damage"] = int32(0)
	original.Stack.NBTData["tag"].(map[string]any)["Unbreakable"] = byte(0)
	original.Stack.NBTData["Lore"].([]string)[0] = "changed"
	original.Stack.CanBePlacedOn[0] = "minecraft:air"
	original.Stack.CanBreak[0] = "minecraft:air"
	want := ItemInstance{StackNetworkID: 7, Stack: cloneTestStack()}
	if !reflect.DeepEqual(cloned, want) {
		t.Fatalf("clone shares stack data: got=%#v want=%#v", cloned, want)
	}
}

func TestItemStack_ClonePreservesStructure(t *testing.T) {
	for _, stack := range []ItemStack{
		{},
		{NBTData: map[string]any{}, CanBePlacedOn: []string{}, CanBreak: []string{}, BlockingTick: 99},
		cloneTestStack(),
	} {
		if cloned := stack.Clone(); !reflect.DeepEqual(cloned, stack) {
			t.Fatalf("Clone changed structure: got=%#v want=%#v", cloned, stack)
		}
		if got, want := stack.Clone(), (ItemInstance{Stack: stack}).Clone().Stack; !reflect.DeepEqual(got, want) {
			t.Fatalf("stack and instance clones differ: got=%#v want=%#v", got, want)
		}
	}
}

func TestItemStack_NormaliseUserDataMatchesItemCodec(t *testing.T) {
	for _, test := range []struct {
		name string
		nbt  map[string]any
	}{
		{"nil", nil},
		{"empty compound", map[string]any{}},
		{"typed lists", map[string]any{"Lore": []string{"original"}, "Unbreakable": true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			x := cloneTestStack()
			x.NBTData = test.nbt
			x.CanBePlacedOn, x.CanBreak = nil, nil
			normalised := x.NormaliseUserData()
			var buffer bytes.Buffer
			NewWriter(&buffer, 0).Item(&x)
			var decoded ItemStack
			NewReader(bytes.NewReader(buffer.Bytes()), 0, false).Item(&decoded)
			decoded.BlockingTick = x.BlockingTick
			if !reflect.DeepEqual(normalised, decoded) {
				t.Fatalf("normalised = %#v; codec = %#v", normalised, decoded)
			}
			if !reflect.DeepEqual(normalised.NormaliseUserData(), normalised) {
				t.Fatal("normalisation is not idempotent")
			}
		})
	}
}

func TestItemStack_NormaliseUserDataDetachesAndPreservesScalars(t *testing.T) {
	x := cloneTestStack()
	normalised := x.NormaliseUserData()
	if normalised.ItemType != x.ItemType || normalised.Count != x.Count ||
		normalised.BlockRuntimeID != x.BlockRuntimeID || normalised.BlockingTick != x.BlockingTick {
		t.Fatalf("normalisation changed scalar values: got=%#v want=%#v", normalised, x)
	}
	x.NBTData["Damage"] = int32(0)
	x.NBTData["tag"].(map[string]any)["Unbreakable"] = byte(0)
	x.NBTData["Lore"].([]string)[0] = "changed"
	x.CanBePlacedOn[0], x.CanBreak[0] = "minecraft:air", "minecraft:air"
	if normalised.NBTData["Damage"] != int32(4) ||
		normalised.NBTData["tag"].(map[string]any)["Unbreakable"] != byte(1) ||
		normalised.NBTData["Lore"].([]any)[0] != "original" ||
		normalised.CanBePlacedOn[0] != "minecraft:stone" || normalised.CanBreak[0] != "minecraft:dirt" {
		t.Fatalf("normalisation retained source references: %#v", normalised)
	}
	air := ItemStack{NBTData: map[string]any{"test": int32(1)}, BlockingTick: 99}.NormaliseUserData()
	if air.NBTData != nil || air.CanBreak != nil || air.CanBePlacedOn != nil || air.BlockingTick != 99 {
		t.Fatalf("air user data = %#v", air)
	}
}

// This guard keeps a new reference field from silently skipping the clone.
func TestItemStack_CloneCoversEveryReferenceField(t *testing.T) {
	covered := map[string]bool{
		"NBTData": true, "CanBePlacedOn": true, "CanBreak": true,
		"Stack.NBTData": true, "Stack.CanBePlacedOn": true, "Stack.CanBreak": true,
	}
	var walk func(reflect.Type, string)
	walk = func(valueType reflect.Type, name string) {
		switch valueType.Kind() {
		case reflect.Struct:
			for i := range valueType.NumField() {
				field := valueType.Field(i)
				prefix := name
				if prefix != "" {
					prefix += "."
				}
				walk(field.Type, prefix+field.Name)
			}
		case reflect.Array:
			walk(valueType.Elem(), name+"[]")
		case reflect.Map, reflect.Slice, reflect.Pointer, reflect.Interface, reflect.Chan, reflect.Func:
			if !covered[name] {
				t.Errorf("item reference field %s has no clone coverage", name)
			}
			delete(covered, name)
		}
	}
	walk(reflect.TypeFor[ItemStack](), "")
	walk(reflect.TypeFor[ItemInstance](), "")
	for name := range covered {
		t.Errorf("clone coverage names missing item field %s", name)
	}
}
