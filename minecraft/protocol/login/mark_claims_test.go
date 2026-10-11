package login

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Marking claims on a shallow copy must preserve the original's serialized claims.
func TestMarkClaimsPreservesCopiedClientData(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		claims []string
	}{
		{name: "one claim", claims: []string{"PlatformType"}},
		{name: "multiple claims", claims: []string{"DefaultInputMode", "PlatformType"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var original ClientData
			input := []byte(`{"DeviceOS":1,"SkinId":"fixture","FixtureClaim":"kept"}`)
			if err := json.Unmarshal(input, &original); err != nil {
				t.Fatal(err)
			}
			// Spare capacity reproduces in-place insertion into a shared backing array.
			order := make([]string, len(original.ClaimOrder), len(original.ClaimOrder)+len(test.claims))
			copy(order, original.ClaimOrder)
			original.ClaimOrder = order
			modified := original
			modified.PlatformType = PlatformTypeMobile
			modified.MarkClaims(test.claims...)
			encoded, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encoded, input) {
				t.Errorf("marking copied data changed original claims: got %s, want %s", encoded, input)
			}
			encoded, err = json.Marshal(modified)
			if err != nil {
				t.Fatal(err)
			}
			claims := map[string]json.RawMessage{}
			if err := json.Unmarshal(encoded, &claims); err != nil {
				t.Fatal(err)
			}
			for _, name := range test.claims {
				if _, ok := claims[name]; !ok {
					t.Errorf("modified data lacks marked claim %s", name)
				}
			}
			if string(claims["SkinId"]) != `"fixture"` || string(claims["FixtureClaim"]) != `"kept"` {
				t.Error("marking claims changed supplied skin or unknown claims")
			}
		})
	}
}
