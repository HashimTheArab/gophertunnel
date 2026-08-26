package p2p

import (
	"encoding/json"
	"testing"
)

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
