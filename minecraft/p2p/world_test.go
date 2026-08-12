package p2p

import (
	"encoding/json"
	"testing"
)

func TestNetherNetIDMarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		id   NetherNetID
		want string
	}{
		{name: "decimal", id: "123456789", want: `123456789`},
		{name: "maximum uint64", id: "18446744073709551615", want: `18446744073709551615`},
		{name: "decimal with leading zeroes", id: "00042", want: `42`},
		{name: "UUID", id: "550e8400-e29b-41d4-a716-446655440000", want: `"550e8400-e29b-41d4-a716-446655440000"`},
		{name: "opaque", id: "network-id", want: `"network-id"`},
		{name: "empty", id: "", want: `""`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := json.Marshal(test.id)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != test.want {
				t.Fatalf("MarshalJSON() = %s, want %s", got, test.want)
			}
		})
	}
}
