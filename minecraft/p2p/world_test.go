package p2p

import (
	"encoding/json"
	"testing"
)

func TestConnectionNetherNetIDUnmarshal(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
		want  string
	}{
		{name: "number", value: `123`, want: "123"},
		{name: "string", value: `"123"`, want: "123"},
		{name: "empty string", value: `""`, want: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			var c Connection
			if err := json.Unmarshal([]byte(`{"ConnectionType":3,"NetherNetId":`+test.value+`}`), &c); err != nil {
				t.Fatalf("UnmarshalJSON() error = %v", err)
			}
			if got := c.NetherNetID.String(); got != test.want {
				t.Fatalf("NetherNetID = %q, want %q", got, test.want)
			}
		})
	}
}
