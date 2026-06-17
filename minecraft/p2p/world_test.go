package p2p

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestConnectionNetherNetIDUnmarshal(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantID    string
		wantValid bool
	}{
		{
			name:   "empty string",
			value:  `""`,
			wantID: "",
		},
		{
			name:   "null",
			value:  `null`,
			wantID: "",
		},
		{
			name:      "quoted number",
			value:     `"12345"`,
			wantID:    "12345",
			wantValid: true,
		},
		{
			name:      "number",
			value:     `12345`,
			wantID:    "12345",
			wantValid: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var c Connection
			if err := json.Unmarshal([]byte(`{"ConnectionType":3,"NetherNetId":`+test.value+`}`), &c); err != nil {
				t.Fatalf("UnmarshalJSON() error = %v", err)
			}
			if got := c.NetherNetID.String(); got != test.wantID {
				t.Fatalf("NetherNetID = %q, want %q", got, test.wantID)
			}
			if got := c.Valid(); got != test.wantValid {
				t.Fatalf("Valid() = %v, want %v", got, test.wantValid)
			}
		})
	}
}

func TestWorldConnectionSelectsFirstSupportedConnection(t *testing.T) {
	messagingID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	w := World{
		TransportLayer: TransportLayerNetherNet,
		SupportedConnections: []Connection{
			{Type: ConnectionTypeSignalingOverLAN},
			{Type: ConnectionTypeSignalingOverJSONRPC, NetherNetID: "111", PlayerMessagingID: messagingID},
			{Type: ConnectionTypeSignalingOverWebSocket, NetherNetID: "222"},
		},
	}

	c, ok := w.Connection()
	if !ok {
		t.Fatal("Connection() did not find a supported connection")
	}
	if c.Type != ConnectionTypeSignalingOverJSONRPC {
		t.Fatalf("Connection().Type = %v, want %v", c.Type, ConnectionTypeSignalingOverJSONRPC)
	}
	if c.PlayerMessagingID != messagingID {
		t.Fatalf("Connection().PlayerMessagingID = %v, want %v", c.PlayerMessagingID, messagingID)
	}
}

func TestWorldConnectionRejectsIncompleteConnections(t *testing.T) {
	w := World{
		TransportLayer: TransportLayerNetherNet,
		SupportedConnections: []Connection{
			{Type: ConnectionTypeSignalingOverJSONRPC, NetherNetID: "111"},
			{Type: ConnectionTypeSignalingOverWebSocket},
		},
	}
	if _, ok := w.Connection(); ok {
		t.Fatal("Connection() found a supported connection for incomplete data")
	}
}
