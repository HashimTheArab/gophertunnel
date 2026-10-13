package nbt

import (
	"reflect"
	"testing"
)

func TestCompound_CloneDecodedTags(t *testing.T) {
	encoded, err := Marshal(map[string]any{
		"byte": byte(1), "short": int16(2), "int": int32(3), "long": int64(4),
		"float": float32(5), "double": float64(6), "string": "value",
		"bytes": [2]byte{7, 8}, "ints": [2]int32{9, 10}, "longs": [2]int64{11, 12},
		"byteList": []byte{13}, "intList": []int32{14}, "longList": []int64{15},
		"list": []any{map[string]any{"nested": []any{"text"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var source Compound
	if err := Unmarshal(encoded, &source); err != nil {
		t.Fatal(err)
	}
	cloned := source.Clone()
	if !reflect.DeepEqual(source, cloned) {
		t.Fatalf("clone changed decoded values or types: source=%#v clone=%#v", source, cloned)
	}
	source["byte"] = byte(0)
	source["byteList"].([]byte)[0] = 0
	source["intList"].([]int32)[0] = 0
	source["longList"].([]int64)[0] = 0
	source["list"].([]any)[0].(map[string]any)["nested"].([]any)[0] = "changed"
	if cloned["byte"] != byte(1) || cloned["byteList"].([]byte)[0] != 13 ||
		cloned["intList"].([]int32)[0] != 14 || cloned["longList"].([]int64)[0] != 15 ||
		cloned["list"].([]any)[0].(map[string]any)["nested"].([]any)[0] != "text" {
		t.Fatalf("clone shares decoded containers: %#v", cloned)
	}
	cloned["list"].([]any)[0].(map[string]any)["added"] = true
	if _, ok := source["list"].([]any)[0].(map[string]any)["added"]; ok {
		t.Fatal("changing the clone changed the source")
	}
}

func TestCompound_ClonePreservesNilAndTypedLists(t *testing.T) {
	if Compound(nil).Clone() != nil {
		t.Fatal("nil compound became non-nil")
	}
	if (Compound{}).Clone() == nil {
		t.Fatal("empty compound became nil")
	}
	source := Compound{
		"nil":         nil,
		"nilCompound": map[string]any(nil), "emptyCompound": map[string]any{},
		"nilList": []any(nil), "emptyList": []any{}, "nilTypedList": []int32(nil),
		"strings": []string{"original"}, "shorts": []int16{1},
		"compounds": []map[string]any{{"name": "original"}},
		"lists":     [][]int64{{2}}, "arrayLists": [][1]int32{{3}},
	}
	cloned := source.Clone()
	if !reflect.DeepEqual(source, cloned) {
		t.Fatalf("clone changed structure: source=%#v clone=%#v", source, cloned)
	}
	source["strings"].([]string)[0] = "changed"
	source["shorts"].([]int16)[0] = 0
	source["compounds"].([]map[string]any)[0]["name"] = "changed"
	source["lists"].([][]int64)[0][0] = 0
	source["arrayLists"].([][1]int32)[0][0] = 0
	if cloned["strings"].([]string)[0] != "original" || cloned["shorts"].([]int16)[0] != 1 ||
		cloned["compounds"].([]map[string]any)[0]["name"] != "original" ||
		cloned["lists"].([][]int64)[0][0] != 2 || cloned["arrayLists"].([][1]int32)[0][0] != 3 {
		t.Fatalf("typed containers remain shared: %#v", cloned)
	}
}

func TestCompound_CloneDecodedContainerAllocations(t *testing.T) {
	encoded, err := Marshal(map[string]any{
		"Damage":  int32(1),
		"display": map[string]any{"Name": "Sword", "Lore": []any{"a", "b", "c"}},
		"ench":    []any{map[string]any{"id": int16(9), "lvl": int16(5)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var decoded, cloned Compound
	if err := Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	allocations := testing.AllocsPerRun(100, func() { cloned = decoded.Clone() })
	if !reflect.DeepEqual(decoded, cloned) {
		t.Fatal("clone changed decoded item tags")
	}
	// Ten allocations detach this tree's maps and lists; reflecting through
	// every map value previously added sixteen allocations to the same copy.
	if allocations > 10 {
		t.Fatalf("decoded item clone allocated %.0f times, want at most 10", allocations)
	}
}
