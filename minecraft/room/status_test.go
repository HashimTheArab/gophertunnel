package room

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/p2p"
)

func TestConnectionMarshalWebSocketUsesRakNetGUID(t *testing.T) {
	t.Parallel()

	b, err := json.Marshal(Status{SupportedConnections: []p2p.Connection{{
		Type:        p2p.ConnectionTypeSignalingOverWebSocket,
		NetherNetID: "6503399194777609304",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	connections := fields["SupportedConnections"].([]any)
	connection := connections[0].(map[string]any)
	if got := connection["RakNetGUID"]; got != "6503399194777609304" {
		t.Fatalf("RakNetGUID = %v, want the WebSocket network ID", got)
	}
	if _, ok := connection["NetherNetId"]; ok {
		t.Fatal("WebSocket connection must not publish NetherNetId")
	}
	if _, ok := connection["PmsgId"]; ok {
		t.Fatal("WebSocket connection must not publish PmsgId")
	}
}

func TestConnectionMarshalJSONRPCUsesMessagingFields(t *testing.T) {
	t.Parallel()

	pmid := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	b, err := json.Marshal(Status{SupportedConnections: []p2p.Connection{{
		Type:              p2p.ConnectionTypeSignalingOverJSONRPC,
		NetherNetID:       "6503399194777609304",
		PlayerMessagingID: pmid,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	connections := fields["SupportedConnections"].([]any)
	connection := connections[0].(map[string]any)
	if got := connection["NetherNetId"]; got != float64(6503399194777609304) {
		t.Fatalf("NetherNetId = %v, want the JSON-RPC network ID", got)
	}
	if got := connection["PmsgId"]; got != pmid.String() {
		t.Fatalf("PmsgId = %v, want %s", got, pmid)
	}
	if _, ok := connection["RakNetGUID"]; ok {
		t.Fatal("JSON-RPC connection must not publish RakNetGUID")
	}
}
