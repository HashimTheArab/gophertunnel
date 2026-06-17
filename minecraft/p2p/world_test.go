package p2p

import (
	"errors"
	"strings"
	"testing"

	"github.com/df-mc/go-xsapi/v2/mpsd"
	"github.com/google/uuid"
)

func TestWorldConnection(t *testing.T) {
	messagingID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	tests := []struct {
		name    string
		world   World
		want    Connection
		wantErr string
	}{
		{
			name: "selects supported JSON-RPC connection",
			world: World{
				TransportLayer: TransportLayerNetherNet,
				SupportedConnections: []Connection{{
					Type:              ConnectionTypeSignalingOverJSONRPC,
					NetherNetID:       "123",
					PlayerMessagingID: messagingID,
				}},
			},
			want: Connection{
				Type:              ConnectionTypeSignalingOverJSONRPC,
				NetherNetID:       "123",
				PlayerMessagingID: messagingID,
			},
		},
		{
			name: "skips unsupported connection before supported connection",
			world: World{
				TransportLayer: TransportLayerNetherNet,
				SupportedConnections: []Connection{
					{Type: 99},
					{
						Type:        ConnectionTypeSignalingOverWebSocket,
						NetherNetID: "123",
					},
				},
			},
			want: Connection{
				Type:        ConnectionTypeSignalingOverWebSocket,
				NetherNetID: "123",
			},
		},
		{
			name: "reports unsupported transport layer",
			world: World{
				TransportLayer: TransportLayerRakNet,
				SupportedConnections: []Connection{{
					Type:        ConnectionTypeSignalingOverWebSocket,
					NetherNetID: "123",
				}},
			},
			wantErr: "transportLayer=0",
		},
		{
			name: "reports unsupported connection metadata",
			world: World{
				TransportLayer: TransportLayerNetherNet,
				SupportedConnections: []Connection{{
					Type: 99,
				}},
			},
			wantErr: "type=99",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.world.Connection()
			if tt.wantErr != "" {
				if !errors.Is(err, ErrNoSupportedConnection) {
					t.Fatalf("Connection() error = %v, want ErrNoSupportedConnection", err)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Connection() error = %q, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Connection() returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("Connection() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestConnectionAddress(t *testing.T) {
	messagingID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	tests := []struct {
		name    string
		conn    Connection
		want    string
		wantErr bool
	}{
		{
			name: "websocket",
			conn: Connection{
				Type:        ConnectionTypeSignalingOverWebSocket,
				NetherNetID: "123",
			},
			want: "123",
		},
		{
			name: "JSON-RPC",
			conn: Connection{
				Type:              ConnectionTypeSignalingOverJSONRPC,
				NetherNetID:       "123",
				PlayerMessagingID: messagingID,
			},
			want: messagingID.String(),
		},
		{
			name: "missing NetherNet ID",
			conn: Connection{
				Type: ConnectionTypeSignalingOverWebSocket,
			},
			wantErr: true,
		},
		{
			name: "unsupported type",
			conn: Connection{
				Type: 99,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.conn.Address()
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidConnection) {
					t.Fatalf("Address() error = %v, want ErrInvalidConnection", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Address() returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("Address() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBroadcastSettingRestrictions(t *testing.T) {
	join, err := BroadcastSettingInviteOnly.JoinRestriction()
	if err != nil {
		t.Fatalf("JoinRestriction() returned error: %v", err)
	}
	if join != mpsd.SessionRestrictionLocal {
		t.Fatalf("JoinRestriction() = %q, want %q", join, mpsd.SessionRestrictionLocal)
	}

	read, err := BroadcastSettingFriendsOfFriends.ReadRestriction()
	if err != nil {
		t.Fatalf("ReadRestriction() returned error: %v", err)
	}
	if read != mpsd.SessionRestrictionFollowed {
		t.Fatalf("ReadRestriction() = %q, want %q", read, mpsd.SessionRestrictionFollowed)
	}

	if _, err := BroadcastSetting(0).JoinRestriction(); !errors.Is(err, ErrInvalidBroadcastSetting) {
		t.Fatalf("JoinRestriction() error = %v, want ErrInvalidBroadcastSetting", err)
	}
	if _, err := BroadcastSetting(0).ReadRestriction(); !errors.Is(err, ErrInvalidBroadcastSetting) {
		t.Fatalf("ReadRestriction() error = %v, want ErrInvalidBroadcastSetting", err)
	}
}
