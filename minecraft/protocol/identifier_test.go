package protocol

import "testing"

func TestValidNamespacedIdentifier(t *testing.T) {
	for _, test := range []struct {
		identifier string
		valid      bool
	}{
		{identifier: "minecraft:stone", valid: true},
		{identifier: "custom:path/to.item", valid: true},
		{identifier: "Custom:stone"},
		{identifier: "minecraft:"},
		{identifier: ":stone"},
		{identifier: "stone"},
	} {
		if got := ValidNamespacedIdentifier(test.identifier); got != test.valid {
			t.Errorf("ValidNamespacedIdentifier(%q) = %v, want %v", test.identifier, got, test.valid)
		}
	}
}
