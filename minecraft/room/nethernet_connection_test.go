package room

import (
	"testing"

	"github.com/google/uuid"
)

func TestNetherNetConnectionInfo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status Status
		wantID string
		wantOK bool
	}{
		{
			name: "websocket nethernet id",
			status: Status{SupportedConnections: []Connection{{
				ConnectionType: ConnectionTypeWebSocketsWebRTCSignaling,
				NetherNetID:    NetherNetID("123456789"),
			}}},
			wantID: "123456789",
			wantOK: true,
		},
		{
			name: "jsonrpc messaging id",
			status: Status{SupportedConnections: []Connection{{
				ConnectionType: ConnectionTypeJSONRPCSignaling,
				NetherNetID:    NetherNetID("123456789"),
				PmsgID:         uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
			}}},
			wantID: "550e8400-e29b-41d4-a716-446655440000",
			wantOK: true,
		},
		{
			name: "jsonrpc without messaging id is rejected",
			status: Status{SupportedConnections: []Connection{{
				ConnectionType: ConnectionTypeJSONRPCSignaling,
				NetherNetID:    NetherNetID("123456789"),
			}}},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := NetherNetConnectionInfo(tt.status)
			if ok != tt.wantOK {
				t.Fatalf("ok mismatch: got %v want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if got.DialID() != tt.wantID {
				t.Fatalf("dial id mismatch: got %q want %q", got.DialID(), tt.wantID)
			}
		})
	}
}
