package p2p

import (
	"encoding/json"
	"testing"
)

func TestWorldSignalingConnectionSkipsUnsupportedTransports(t *testing.T) {
	var w World
	data := []byte(`{
		"TransportLayer": 2,
		"SupportedConnections": [
			{"ConnectionType": 6, "HostIpAddress": "192.0.2.1", "HostPort": 19132},
			{"ConnectionType": 7, "NetherNetId": "12345", "PmsgId": "01890fa5-bae8-735c-99dc-29f89c4830bd"}
		]
	}`)
	if err := json.Unmarshal(data, &w); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	conn, ok := w.signalingConnection()
	if !ok {
		t.Fatal("no signaling connection found")
	}
	if conn.Type != ConnectionTypeSignalingOverJSONRPC {
		t.Fatalf("selected connection type %d, want %d", conn.Type, ConnectionTypeSignalingOverJSONRPC)
	}
	if got := conn.Address(); got != "01890fa5-bae8-735c-99dc-29f89c4830bd" {
		t.Fatalf("Address() = %q", got)
	}
}

func TestWorldSignalingConnectionRejectsIncompleteSignalingTransports(t *testing.T) {
	w := World{TransportLayer: TransportLayerNetherNet, SupportedConnections: []Connection{
		{Type: ConnectionTypeSignalingOverJSONRPC, NetherNetID: "12345"},
		{Type: ConnectionTypeSignalingOverWebSocket},
	}}
	if conn, ok := w.signalingConnection(); ok {
		t.Fatalf("selected incomplete connection: %#v", conn)
	}
}

func TestWorldSignalingConnectionRejectsNonNetherNetWorlds(t *testing.T) {
	w := World{
		TransportLayer: TransportLayerRakNet,
		SupportedConnections: []Connection{
			{Type: ConnectionTypeSignalingOverWebSocket, NetherNetID: "12345"},
		},
	}
	if conn, ok := w.signalingConnection(); ok {
		t.Fatalf("selected connection for non-NetherNet world: %#v", conn)
	}
}
