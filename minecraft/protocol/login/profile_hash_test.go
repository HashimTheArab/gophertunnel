package login

import (
	"encoding/json"
	"testing"
)

// TestClientDataPreservesEmptyProfileHash covers classic-skin logins to servers requiring the claim.
func TestClientDataPreservesEmptyProfileHash(t *testing.T) {
	for _, value := range []string{"", "persona-profile"} {
		t.Run(value, func(t *testing.T) {
			input, err := json.Marshal(map[string]string{"ProfileHash": value})
			if err != nil {
				t.Fatal(err)
			}
			var data ClientData
			if err := json.Unmarshal(input, &data); err != nil {
				t.Fatal(err)
			}
			for _, updated := range []string{value, "changed-profile", ""} {
				data.ProfileHash = updated
				encoded, err := json.Marshal(data)
				if err != nil {
					t.Fatal(err)
				}
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(encoded, &fields); err != nil {
					t.Fatal(err)
				}
				want, _ := json.Marshal(updated)
				if string(fields["ProfileHash"]) != string(want) {
					t.Fatalf("ProfileHash = %s, want %s", fields["ProfileHash"], want)
				}
			}
		})
	}
}
