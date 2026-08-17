package room

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/p2p"
)

func TestStatusMarshalMinecraftSessionFields(t *testing.T) {
	t.Parallel()

	pmsgID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	custom, err := json.Marshal(Status{
		Hardcore: true,
		Nonces:   map[string]string{"200": "0102030405060708"},
		SupportedConnections: []p2p.Connection{{
			Type:              p2p.ConnectionTypeSignalingOverJSONRPC,
			NetherNetID:       "123456789",
			PlayerMessagingID: pmsgID,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]json.RawMessage
	if err := json.Unmarshal(custom, &got); err != nil {
		t.Fatal(err)
	}
	if string(got["isHardcore"]) != "true" {
		t.Fatalf("isHardcore = %s, want true", got["isHardcore"])
	}
	if string(got["nonces"]) != `{"200":"0102030405060708"}` {
		t.Fatalf("nonces = %s", got["nonces"])
	}
	var connections []map[string]json.RawMessage
	if err := json.Unmarshal(got["SupportedConnections"], &connections); err != nil {
		t.Fatal(err)
	}
	if string(connections[0]["NetherNetId"]) != "123456789" {
		t.Fatalf("NetherNetId = %s, want JSON number", connections[0]["NetherNetId"])
	}
	if string(connections[0]["PmsgId"]) != `"550e8400-e29b-41d4-a716-446655440000"` {
		t.Fatalf("PmsgId = %s", connections[0]["PmsgId"])
	}
}

func TestStatusMarshalEmptyNoncesAsObject(t *testing.T) {
	t.Parallel()

	custom, err := json.Marshal(Status{Nonces: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(custom, &got); err != nil {
		t.Fatal(err)
	}
	if string(got["nonces"]) != "{}" {
		t.Fatalf("nonces = %s, want empty object", got["nonces"])
	}
}
