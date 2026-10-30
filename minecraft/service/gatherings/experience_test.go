package gatherings

import (
	"encoding/json"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/realms"
)

// TestAddressDialAddress pins vanilla's choice of transport and of which fields it reads per protocol.
func TestAddressDialAddress(t *testing.T) {
	const id = "550e8400-e29b-41d4-a716-446655440000"
	tests := []struct {
		name          string
		address       Address
		wantTransport Transport
		want          string
		wantErr       bool
	}{
		{name: "Default", address: Address{NetworkProtocol: NetworkProtocolDefault, IPv4Address: "127.0.0.1", Port: 19132}, wantTransport: TransportRakNet, want: "127.0.0.1:19132"},
		{name: "Default hostname", address: Address{NetworkProtocol: NetworkProtocolDefault, IPv4Address: "play.example.com", Port: 19132}, wantTransport: TransportRakNet, want: "play.example.com:19132"},
		{name: "missing protocol is Default", address: Address{IPv4Address: "play.example.com", Port: 19132}, wantTransport: TransportRakNet, want: "play.example.com:19132"},
		{name: "Default ignores ID", address: Address{NetworkProtocol: NetworkProtocolDefault, NetherNetID: id, IPv4Address: "play.example.com", Port: 19132}, wantTransport: TransportRakNet, want: "play.example.com:19132"},
		{name: "Default ID only", address: Address{NetworkProtocol: NetworkProtocolDefault, NetherNetID: id}, wantErr: true},
		{name: "Default missing port", address: Address{NetworkProtocol: NetworkProtocolDefault, IPv4Address: "play.example.com"}, wantErr: true},
		{name: "Default whitespace host", address: Address{NetworkProtocol: NetworkProtocolDefault, IPv4Address: "   ", Port: 19132}, wantErr: true},
		{name: "NetherNet", address: Address{NetworkProtocol: "NetherNet", IPv4Address: "play.example.com", Port: 19132}, wantTransport: TransportNetherNet, want: "play.example.com:19132"},
		{name: "NetherNet ignores ID", address: Address{NetworkProtocol: "NetherNet", NetherNetID: "123456789", IPv4Address: "play.example.com", Port: 19132}, wantTransport: TransportNetherNet, want: "play.example.com:19132"},
		{name: "NetherNet ID only", address: Address{NetworkProtocol: "NetherNet", NetherNetID: "123456789"}, wantErr: true},
		{name: "NetherNet missing host", address: Address{NetworkProtocol: "NetherNet", Port: 19132}, wantErr: true},
		{name: "NetherNet missing port", address: Address{NetworkProtocol: "NetherNet", IPv4Address: "play.example.com"}, wantErr: true},
		{name: "NetherNet whitespace host", address: Address{NetworkProtocol: "NetherNet", IPv4Address: "   ", Port: 19132}, wantErr: true},
		{name: "NetherNet_JsonRpc", address: Address{NetworkProtocol: "NetherNet_JsonRpc", NetherNetID: id}, wantTransport: TransportNetherNetJSONRPC, want: id},
		{name: "NetherNet_JsonRpc any case", address: Address{NetworkProtocol: "NETHERNET_JSONRPC", NetherNetID: id}, wantTransport: TransportNetherNetJSONRPC, want: id},
		{name: "NetherNet_JsonRpc ignores host", address: Address{NetworkProtocol: "NetherNet_JsonRpc", NetherNetID: id, IPv4Address: "play.example.com", Port: 19132}, wantTransport: TransportNetherNetJSONRPC, want: id},
		{name: "NetherNet_JsonRpc host only", address: Address{NetworkProtocol: "NetherNet_JsonRpc", IPv4Address: "play.example.com", Port: 19132}, wantErr: true},
		{name: "NetherNet_JsonRpc whitespace ID", address: Address{NetworkProtocol: "NetherNet_JsonRpc", NetherNetID: "   "}, wantErr: true},
		{name: "unsupported", address: Address{NetworkProtocol: "QUIC", IPv4Address: "127.0.0.1", Port: 19132}, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport, got, err := test.address.DialAddress()
			if (err != nil) != test.wantErr {
				t.Fatalf("DialAddress() error = %v, wantErr %t", err, test.wantErr)
			}
			if transport != test.wantTransport || got != test.want {
				t.Fatalf("DialAddress() = %d, %q, want %d, %q", transport, got, test.wantTransport, test.want)
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
	transport, got, err := address.DialAddress()
	if err != nil || transport != TransportRakNet || got != "play.example.com:19132" {
		t.Fatalf("DialAddress() = %d, %q, %v, want RakNet play.example.com:19132", transport, got, err)
	}
}

func TestAddressUnmarshalJSONNetherNetID(t *testing.T) {
	var address Address
	if err := json.Unmarshal([]byte(`{
		"networkProtocol":"NetherNet_JsonRpc",
		"netherNetId":"550e8400-e29b-41d4-a716-446655440000"
	}`), &address); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got, want := address.NetherNetID, "550e8400-e29b-41d4-a716-446655440000"; got != want {
		t.Fatalf("NetherNetID = %q, want %q", got, want)
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
