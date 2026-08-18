package protocol

import "testing"

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
