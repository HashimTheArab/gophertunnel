package minecraft

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

func TestDefaultClientDataSelfSignedID(t *testing.T) {
	for _, test := range []struct {
		name string
		data login.ClientData
		want string
	}{
		{name: "derive", data: login.ClientData{ClientRandomID: 0x0102030405060708, DeviceID: "audit-device-id"}, want: "62c686b6-9dd2-3c26-ac8d-6da654ca1b3f"},
		{name: "explicit", data: login.ClientData{ClientRandomID: -1, DeviceID: "audit-device-id", SelfSignedID: "00000000-0000-4000-8000-000000000001"}, want: "00000000-0000-4000-8000-000000000001"},
		{name: "explicit without device", data: login.ClientData{SelfSignedID: "00000000-0000-4000-8000-000000000001"}, want: "00000000-0000-4000-8000-000000000001"},
		{name: "decoded zero", data: login.ClientData{DeviceID: "audit-device-id", ClaimOrder: []string{"ClientRandomId", "DeviceId", "SelfSignedId"}}, want: "6e6069e0-2a0c-3fca-97bd-72c46440d781"},
	} {
		t.Run(test.name, func(t *testing.T) {
			defaultClientData("example.com:19132", "Player", &test.data)
			if test.data.SelfSignedID != test.want {
				t.Fatalf("SelfSignedID = %q, want %q", test.data.SelfSignedID, test.want)
			}
		})
	}
}

func TestDefaultClientDataSelfSignedIDWithoutDevice(t *testing.T) {
	data := login.ClientData{ClientRandomID: -1}
	defaultClientData("example.com:19132", "Player", &data)
	id, err := uuid.Parse(data.SelfSignedID)
	if err != nil {
		t.Fatal(err)
	}
	if id.Version() != 4 || id.Variant() != uuid.RFC4122 {
		t.Fatalf("missing-device fallback version/variant = %v/%v", id.Version(), id.Variant())
	}
}

func TestDialContextSelfSignedIDStableAcrossDials(t *testing.T) {
	dialer := Dialer{
		FlushRate:  -1,
		ClientData: login.ClientData{ClientRandomID: 0x0102030405060708, DeviceID: "audit-device-id"},
	}
	for range 2 {
		network := newScriptedDialNetwork(func(conn net.Conn) error {
			decoder, encoder, err := startScriptedLogin(conn)
			if err != nil {
				return err
			}
			if err := encodeScriptedPackets(encoder,
				&packet.ItemRegistry{},
				&packet.ChunkRadiusUpdated{ChunkRadius: 16},
				&packet.PlayStatus{Status: packet.PlayStatusPlayerSpawn},
			); err != nil {
				return fmt.Errorf("finish login: %w", err)
			}
			if _, err := decoder.Decode(); err != nil {
				return fmt.Errorf("read login acknowledgement: %w", err)
			}
			return expectScriptedClose(conn, decoder)
		})
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		conn, err := dialer.DialContextNetwork(ctx, network, "example.com:19132")
		if err != nil {
			cancel()
			t.Fatalf("dial: %v", err)
		}
		got := conn.ClientData().SelfSignedID
		_ = conn.Close()
		cancel()
		if err := <-network.done; err != nil {
			t.Fatal(err)
		}
		if want := "62c686b6-9dd2-3c26-ac8d-6da654ca1b3f"; got != want {
			t.Fatalf("SelfSignedID = %q, want %q", got, want)
		}
	}
}
