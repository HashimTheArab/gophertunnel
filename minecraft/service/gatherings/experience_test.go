package gatherings

import "testing"

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
				IPv4Address:     "550e8400-e29b-41d4-a716-446655440000",
			},
			want: "550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name: "NetherNet WebSocket",
			address: Address{
				NetworkProtocol: "nethernet",
				IPv4Address:     "123456789",
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

func TestParseNetworkProtocol(t *testing.T) {
	tests := []struct {
		input string
		want  NetworkProtocol
	}{
		{input: "Default", want: NetworkProtocolDefault},
		{input: " default ", want: NetworkProtocolDefault},
		{input: "NetherNet", want: NetworkProtocolNetherNet},
		{input: "NETHERNET_JSONRPC", want: NetworkProtocolNetherNetJSONRPC},
		{input: "NetherNet_JsonRpc", want: NetworkProtocolNetherNetJSONRPC},
	}

	for _, test := range tests {
		if got := ParseNetworkProtocol(test.input); got != test.want {
			t.Errorf("ParseNetworkProtocol(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}
