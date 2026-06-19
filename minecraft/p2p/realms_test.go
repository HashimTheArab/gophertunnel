package p2p

import (
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/realms"
)

func TestConnectionTypeFromRealmProtocol(t *testing.T) {
	tests := []struct {
		name     string
		protocol realms.NetworkProtocol
		want     int
		wantOK   bool
	}{
		{
			name:     "websocket",
			protocol: realms.NetworkProtocolNetherNet,
			want:     ConnectionTypeSignalingOverWebSocket,
			wantOK:   true,
		},
		{
			name:     "jsonrpc",
			protocol: realms.NetworkProtocolNetherNetJSONRPC,
			want:     ConnectionTypeSignalingOverJSONRPC,
			wantOK:   true,
		},
		{
			name:     "case insensitive",
			protocol: "nethernet_jsonrpc",
			want:     ConnectionTypeSignalingOverJSONRPC,
			wantOK:   true,
		},
		{
			name:     "default",
			protocol: realms.NetworkProtocolDefault,
			wantOK:   false,
		},
		{
			name:     "unknown",
			protocol: "SOMETHING_ELSE",
			wantOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ConnectionTypeFromRealmProtocol(tt.protocol)
			if ok != tt.wantOK {
				t.Fatalf("ok mismatch: got %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("connection type mismatch: got %d, want %d", got, tt.want)
			}
		})
	}
}
