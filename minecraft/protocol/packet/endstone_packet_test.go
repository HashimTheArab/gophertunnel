package packet

import (
	"bytes"
	"testing"

	"github.com/go-gl/mathgl/mgl32"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

func marshalPacket(pk Packet) []byte {
	var b bytes.Buffer
	pk.Marshal(protocol.NewWriter(&b, 0))
	return b.Bytes()
}

func requireMarshalBytes(t *testing.T, pk Packet, want []byte) {
	t.Helper()
	if got := marshalPacket(pk); !bytes.Equal(got, want) {
		t.Fatalf("%T marshal mismatch:\ngot  % x\nwant % x", pk, got, want)
	}
}

func TestEndstoneUnsignedVaruintPacketFields(t *testing.T) {
	tests := []struct {
		name string
		pk   Packet
		want []byte
	}{
		{
			name: "disconnect reason",
			pk:   &Disconnect{Reason: 300, HideDisconnectionScreen: true},
			want: []byte{0xac, 0x02, 0x01},
		},
		{
			name: "legacy telemetry event type",
			pk: &Event{
				Event: &protocol.ItemUsedEvent{},
			},
			want: []byte{
				0,
				0x1f,
				0,
				0x14,
				0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0,
			},
		},
		{
			name: "multiplayer settings packet type",
			pk:   &MultiPlayerSettings{ActionType: 300},
			want: []byte{0xac, 0x02},
		},
		{
			name: "npc dialogue action type",
			pk:   &NPCDialogue{ActionType: 300},
			want: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0xac, 0x02, 0, 0, 0, 0},
		},
		{
			name: "server bound loading screen type",
			pk:   &ServerBoundLoadingScreen{Type: 300},
			want: []byte{0xac, 0x02, 0},
		},
		{
			name: "movement effect type",
			pk:   &MovementEffect{Type: 300, Duration: 1},
			want: []byte{0, 0xac, 0x02, 0x02, 0},
		},
		{
			name: "packet violation warning enums",
			pk:   &PacketViolationWarning{Type: 300, Severity: 300, PacketID: 300},
			want: []byte{0xac, 0x02, 0xac, 0x02, 0xd8, 0x04, 0},
		},
		{
			name: "player action type",
			pk:   &PlayerAction{ActionType: 300, BlockFace: 1},
			want: []byte{0, 0xac, 0x02, 0, 0, 0, 0, 0, 0, 0x02},
		},
		{
			name: "set default game type",
			pk:   &SetDefaultGameType{GameType: 300},
			want: []byte{0xac, 0x02},
		},
		{
			name: "set last hurt by",
			pk:   &SetLastHurtBy{EntityType: 300},
			want: []byte{0xac, 0x02},
		},
		{
			name: "set player game type",
			pk:   &SetPlayerGameType{GameType: 300},
			want: []byte{0xac, 0x02},
		},
		{
			name: "set spawn position type",
			pk:   &SetSpawnPosition{SpawnType: 300},
			want: []byte{0xac, 0x02, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name: "set title action type",
			pk:   &SetTitle{ActionType: 300},
			want: []byte{0xac, 0x02, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name: "update player game type",
			pk:   &UpdatePlayerGameType{GameType: 300},
			want: []byte{0xac, 0x02, 0, 0},
		},
		{
			name: "set hud enums",
			pk:   &SetHud{Elements: []uint32{300}, Visibility: 300},
			want: []byte{0x01, 0xac, 0x02, 0xac, 0x02},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireMarshalBytes(t, tt.pk, tt.want)
		})
	}
}

func TestEndstoneFixedWidthPacketFields(t *testing.T) {
	requireMarshalBytes(t, &AgentAction{
		Identifier: "request",
		Action:     300,
		Response:   "ok",
	}, []byte{
		0x07, 'r', 'e', 'q', 'u', 'e', 's', 't',
		0x2c, 0x01, 0x00, 0x00,
		0x02, 'o', 'k',
	})

	requireMarshalBytes(t, &BossEvent{
		EventType: 300,
		Colour:    300,
		Overlay:   300,
	}, []byte{
		0, 0,
		0xac, 0x02,
		0, 0,
		0, 0, 0, 0,
		0xac, 0x02,
		0xac, 0x02,
	})
}

func TestServerPlayerPostMovePosition(t *testing.T) {
	pk := &ServerPlayerPostMovePosition{Position: mgl32.Vec3{1, 2, 3}}
	if pk.ID() != 16 {
		t.Fatalf("ServerPlayerPostMovePosition ID = %d, want 16", pk.ID())
	}
	requireMarshalBytes(t, pk, []byte{
		0x00, 0x00, 0x80, 0x3f,
		0x00, 0x00, 0x00, 0x40,
		0x00, 0x00, 0x40, 0x40,
	})
}
