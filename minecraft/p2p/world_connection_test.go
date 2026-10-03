package p2p

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestNetherNetIDMarshalJSONPreservesVanillaNumberShape(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		id   NetherNetID
		want []byte
	}{
		{name: "decimal", id: "6503399194777609304", want: []byte(`6503399194777609304`)},
		{name: "opaque", id: "11111111-2222-3333-4444-555555555555", want: []byte(`"11111111-2222-3333-4444-555555555555"`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.id)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("MarshalJSON() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestNetherNetIDRejectsInvalidDecimalForms(t *testing.T) {
	t.Parallel()

	for _, id := range []NetherNetID{"0", "01"} {
		id := id
		t.Run(string(id), func(t *testing.T) {
			t.Parallel()
			if err := id.Validate(); err == nil {
				t.Fatalf("Validate(%q) succeeded", id)
			}
			if _, err := json.Marshal(id); err == nil {
				t.Fatalf("MarshalJSON(%q) succeeded", id)
			}
		})
	}
}

func TestConnectionUnmarshalWebSocketUsesRakNetGUID(t *testing.T) {
	t.Parallel()

	var connection Connection
	err := json.Unmarshal([]byte(`{
		"ConnectionType": 3,
		"HostIpAddress": "",
		"HostPort": 0,
		"RakNetGUID": "6503399194777609304"
	}`), &connection)
	if err != nil {
		t.Fatal(err)
	}
	if got := connection.NetherNetID; got != "6503399194777609304" {
		t.Fatalf("NetherNetID = %q, want the RakNetGUID network ID", got)
	}
	if err := connection.Validate(); err != nil {
		t.Fatalf("validate WebSocket connection: %v", err)
	}
	if got := connection.Address(); got != "6503399194777609304" {
		t.Fatalf("Address = %q, want the WebSocket network ID", got)
	}
}
