package nbt

import (
	"bytes"
	"reflect"
	"testing"
)

func TestCompound_DecodeMatchesLegacyMaps(t *testing.T) {
	for _, test := range []struct {
		name     string
		encoding Encoding
	}{
		{"network little endian", NetworkLittleEndian},
		{"network big endian", NetworkBigEndian},
		{"little endian", LittleEndian},
		{"big endian", BigEndian},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoding := test.encoding
			data, err := MarshalEncoding(Compound{
				"Damage":  int32(1),
				"display": Compound{"Name": "Sword", "Lore": []string{"a", "b"}},
				"ench":    []any{map[string]any{"id": int16(9), "lvl": int16(5)}},
			}, encoding)
			if err != nil {
				t.Fatal(err)
			}
			var legacy map[string]any
			var compound Compound
			if err := UnmarshalEncoding(data, &legacy, encoding); err != nil {
				t.Fatal(err)
			}
			if err := UnmarshalEncoding(data, &compound, encoding); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(map[string]any(compound), legacy) {
				t.Fatalf("named compound changed decoded shapes: got=%#v want=%#v", compound, legacy)
			}
			if _, ok := compound["display"].(map[string]any); !ok {
				t.Fatal("generic nested compound changed its map type")
			}
		})
	}
}

func TestCompound_DecodeReplacesPreviousMap(t *testing.T) {
	var stream bytes.Buffer
	encoder := NewEncoder(&stream)
	for _, compound := range []Compound{{"old": int32(1)}, {"new": int32(2)}} {
		if err := encoder.Encode(compound); err != nil {
			t.Fatal(err)
		}
	}
	decoder := NewDecoder(&stream)
	var compound Compound
	if err := decoder.Decode(&compound); err != nil {
		t.Fatal(err)
	}
	previous := compound
	if err := decoder.Decode(&compound); err != nil {
		t.Fatal(err)
	}
	if !compound.Equal(Compound{"new": int32(2)}) || !previous.Equal(Compound{"old": int32(1)}) {
		t.Fatal("decode reused the previous map or retained stale fields")
	}
}

func TestCompound_DecodeAllowZeroClearsMap(t *testing.T) {
	for _, initial := range []Compound{nil, {"stale": int32(1)}} {
		compound := initial
		decoder := NewDecoder(bytes.NewReader([]byte{0}))
		decoder.AllowZero = true
		if err := decoder.Decode(&compound); err != nil {
			t.Fatal(err)
		}
		if compound == nil || len(compound) != 0 {
			t.Fatalf("zero tree retained nil or stale data: %#v", compound)
		}
	}
}

func TestCompound_DecodeRetainsAllocationBudget(t *testing.T) {
	data, err := Marshal(Compound{
		"Damage": int32(1), "display": map[string]any{"Name": "Sword", "Lore": []string{"a", "b"}},
		"ench": []any{map[string]any{"id": int16(9), "lvl": int16(5)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]any
	var compound Compound
	legacyAllocations := testing.AllocsPerRun(100, func() {
		if err := Unmarshal(data, &legacy); err != nil {
			t.Fatal(err)
		}
	})
	compoundAllocations := testing.AllocsPerRun(100, func() {
		if err := Unmarshal(data, &compound); err != nil {
			t.Fatal(err)
		}
	})
	if compoundAllocations > legacyAllocations {
		t.Fatalf("named compound allocated %.0f times, legacy map allocated %.0f", compoundAllocations, legacyAllocations)
	}
}

func TestCompound_ClonePreservesNestedCompoundType(t *testing.T) {
	source := Compound{"named": Compound{"bytes": []byte{1}}, "map": map[string]any{"bytes": []byte{2}}}
	cloned := source.Clone()
	if !reflect.DeepEqual(source, cloned) {
		t.Fatal("clone changed a nested compound type")
	}
	source["named"].(Compound)["bytes"].([]byte)[0] = 3
	source["map"].(map[string]any)["bytes"].([]byte)[0] = 4
	if cloned["named"].(Compound)["bytes"].([]byte)[0] != 1 || cloned["map"].(map[string]any)["bytes"].([]byte)[0] != 2 {
		t.Fatal("clone retained nested mutable storage")
	}
}
