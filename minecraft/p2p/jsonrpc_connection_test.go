package p2p

import (
	"testing"

	"github.com/google/uuid"
)

type testJSONRPCSignaling struct {
	networkID         string
	playerMessagingID uuid.UUID
}

func (s testJSONRPCSignaling) NetworkID() string {
	return s.networkID
}

func (s testJSONRPCSignaling) PlayerMessagingID() uuid.UUID {
	return s.playerMessagingID
}

func TestNewJSONRPCConnection(t *testing.T) {
	pmid := uuid.New()
	got, err := NewJSONRPCConnection(testJSONRPCSignaling{
		networkID:         "1234567890",
		playerMessagingID: pmid,
	})
	if err != nil {
		t.Fatalf("NewJSONRPCConnection returned an error: %v", err)
	}
	want := Connection{
		Type:              ConnectionTypeSignalingOverJSONRPC,
		NetherNetID:       "1234567890",
		PlayerMessagingID: pmid,
	}
	if got != want {
		t.Fatalf("NewJSONRPCConnection returned %#v, want %#v", got, want)
	}
}

func TestNewJSONRPCConnectionRejectsNilSignaling(t *testing.T) {
	if _, err := NewJSONRPCConnection(nil); err == nil {
		t.Fatal("NewJSONRPCConnection unexpectedly accepted nil signaling")
	}
}
