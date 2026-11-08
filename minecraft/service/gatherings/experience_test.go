package gatherings

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/realms"
)

// networks returns Networks whose JSON-RPC route opens signaling that fails with errSignaling.
func networks() realms.Networks {
	return realms.Networks{DialSignaling: func(context.Context) (minecraft.SignalingConn, error) { return nil, errSignaling }}
}

var errSignaling = errors.New("test signaling")

// TestAddressNetwork pins which assignment fields vanilla reads per protocol and the network each gets.
func TestAddressNetwork(t *testing.T) {
	const id = "550e8400-e29b-41d4-a716-446655440000"
	tests := []struct {
		name    string
		address Address
		want    string // the network's type name
		target  string
	}{
		{name: "Default", address: Address{NetworkProtocol: "Default", IPv4Address: "127.0.0.1", Port: 19132}, want: "RakNet", target: "127.0.0.1:19132"},
		{name: "Default hostname", address: Address{NetworkProtocol: "Default", IPv4Address: "play.example.com", Port: 19132}, want: "RakNet", target: "play.example.com:19132"},
		{name: "missing protocol is Default", address: Address{IPv4Address: "play.example.com", Port: 19132}, want: "RakNet", target: "play.example.com:19132"},
		{name: "Default ignores ID", address: Address{NetworkProtocol: "Default", NetherNetID: id, IPv4Address: "play.example.com", Port: 19132}, want: "RakNet", target: "play.example.com:19132"},
		{name: "Default ID only", address: Address{NetworkProtocol: "Default", NetherNetID: id}},
		{name: "Default missing port", address: Address{NetworkProtocol: "Default", IPv4Address: "play.example.com"}},
		{name: "Default whitespace host", address: Address{NetworkProtocol: "Default", IPv4Address: "   ", Port: 19132}},
		{name: "NetherNet", address: Address{NetworkProtocol: "NetherNet", IPv4Address: "play.example.com", Port: 19132}, want: "NetherNetHTTP", target: "play.example.com:19132"},
		{name: "NetherNet ignores ID", address: Address{NetworkProtocol: "NetherNet", NetherNetID: "123456789", IPv4Address: "play.example.com", Port: 19132}, want: "NetherNetHTTP", target: "play.example.com:19132"},
		{name: "NetherNet ID only", address: Address{NetworkProtocol: "NetherNet", NetherNetID: "123456789"}},
		{name: "NetherNet missing port", address: Address{NetworkProtocol: "NetherNet", IPv4Address: "play.example.com"}},
		{name: "NetherNet whitespace host", address: Address{NetworkProtocol: "NetherNet", IPv4Address: "   ", Port: 19132}},
		{name: "NetherNet_JsonRpc", address: Address{NetworkProtocol: "NetherNet_JsonRpc", NetherNetID: id}, want: "NetherNet", target: id},
		{name: "NetherNet_JsonRpc ignores host", address: Address{NetworkProtocol: "NetherNet_JsonRpc", NetherNetID: id, IPv4Address: "play.example.com", Port: 19132}, want: "NetherNet", target: id},
		{name: "NetherNet_JsonRpc host only", address: Address{NetworkProtocol: "NetherNet_JsonRpc", IPv4Address: "play.example.com", Port: 19132}},
		{name: "unsupported", address: Address{NetworkProtocol: "QUIC", IPv4Address: "127.0.0.1", Port: 19132}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			network, target, err := test.address.Network(networks())
			if test.want == "" {
				if err == nil {
					t.Fatalf("Network() = %T, %q, want an error", network, target)
				}
				return
			}
			if err != nil {
				t.Fatalf("Network(): %v", err)
			}
			if got := reflect.TypeOf(network).Name(); got != test.want || target != test.target {
				t.Fatalf("Network() = %s, %q, want %s, %q", got, target, test.want, test.target)
			}
			if n, ok := network.(minecraft.NetherNet); ok {
				if _, err := n.DialSignaling(t.Context(), target); !errors.Is(err, errSignaling) {
					t.Fatalf("NetherNet signaling error = %v, want the caller's", err)
				}
			}
		})
	}
}

// TestAddressUnmarshalJSONMissingProtocol guards that a body without networkProtocol dials RakNet.
func TestAddressUnmarshalJSONMissingProtocol(t *testing.T) {
	var address Address
	if err := json.Unmarshal([]byte(`{"ipV4Address":"play.example.com","port":19132}`), &address); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	network, target, err := address.Network(networks())
	if _, ok := network.(minecraft.RakNet); err != nil || !ok || target != "play.example.com:19132" {
		t.Fatalf("Network() = %T, %q, %v, want RakNet play.example.com:19132", network, target, err)
	}
}

// A NetherNet_JsonRpc assignment carries its netherNetId as a UUID string and is dialed at that ID.
func TestAddressUnmarshalJSONNetherNetID(t *testing.T) {
	const id = "550e8400-e29b-41d4-a716-446655440000"
	var address Address
	if err := json.Unmarshal([]byte(`{
		"networkProtocol":"NetherNet_JsonRpc",
		"netherNetId":"`+id+`"
	}`), &address); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if address.NetherNetID != id {
		t.Fatalf("NetherNetID = %q, want %q", address.NetherNetID, id)
	}
	network, target, err := address.Network(networks())
	if _, ok := network.(minecraft.NetherNet); err != nil || !ok || target != id {
		t.Fatalf("Network() = %T, %q, %v; want JSON-RPC NetherNet to %q", network, target, err, id)
	}
}

func TestAddressNetworkProtocol(t *testing.T) {
	tests := []struct {
		input string
		want  realms.NetworkProtocol
	}{
		{input: "Default", want: realms.NetworkProtocolDefault},
		{input: " default ", want: realms.NetworkProtocolDefault},
		{input: "NetherNet", want: realms.NetworkProtocolNetherNet},
		{input: "NETHERNET_JSONRPC", want: realms.NetworkProtocolNetherNetJSONRPC},
		{input: "NetherNet_JsonRpc", want: realms.NetworkProtocolNetherNetJSONRPC},
	}

	for _, test := range tests {
		if got := realms.ParseNetworkProtocol(test.input); got != test.want {
			t.Errorf("realms.ParseNetworkProtocol(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}
