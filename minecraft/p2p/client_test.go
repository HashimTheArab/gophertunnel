package p2p

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestSessionUpdateWorldDataWaitsForConnection(t *testing.T) {
	t.Parallel()

	s := &Session{
		nonce: "nonce",
		ready: make(chan struct{}),
	}

	if err := s.updateWorldData(json.RawMessage(`{}`)); err != nil {
		t.Fatalf("update without connection: %v", err)
	}
	select {
	case <-s.ready:
		t.Fatal("session became ready without a usable connection")
	default:
	}

	if err := s.updateWorldData(mustMarshalWorld(t, World{
		TransportLayer: TransportLayerNetherNet,
		SupportedConnections: []Connection{{
			Type:              ConnectionTypeSignalingOverJSONRPC,
			NetherNetID:       "123456789",
			PlayerMessagingID: uuid.MustParse("00000000-0000-0000-0000-000000000001"),
		}},
	})); err != nil {
		t.Fatalf("update with connection: %v", err)
	}
	select {
	case <-s.ready:
	default:
		t.Fatal("session did not become ready after usable connection arrived")
	}
}

func mustMarshalWorld(t *testing.T, world World) json.RawMessage {
	t.Helper()

	b, err := json.Marshal(world)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
