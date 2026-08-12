package gatherings

import (
	"encoding/json"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/realms"
)

func TestAddressDialAddress(t *testing.T) {
	tests := []struct {
		name    string
		address Address
		want    string
		wantErr bool
	}{
		{
			name: "RakNet",
			address: Address{
				NetworkProtocol: NetworkProtocolDefault,
				IPv4Address:     "127.0.0.1",
				Port:            19132,
			},
			want: "127.0.0.1:19132",
		},
		{
			name: "NetherNet JSON-RPC",
			address: Address{
				NetworkProtocol: "NETHERNET_JSONRPC",
				NetherNetID:     "550e8400-e29b-41d4-a716-446655440000",
			},
			want: "550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name: "NetherNet WebSocket",
			address: Address{
				NetworkProtocol: "nethernet",
				NetherNetID:     "123456789",
			},
			want: "123456789",
		},
		{
			name: "unsupported",
			address: Address{
				NetworkProtocol: "QUIC",
				IPv4Address:     "127.0.0.1",
				Port:            19132,
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.address.DialAddress()
			if (err != nil) != test.wantErr {
				t.Fatalf("DialAddress() error = %v, wantErr %t", err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("DialAddress() = %q, want %q", got, test.want)
			}
			if gotString := test.address.String(); gotString != test.want {
				t.Fatalf("String() = %q, want %q", gotString, test.want)
			}
		})
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
