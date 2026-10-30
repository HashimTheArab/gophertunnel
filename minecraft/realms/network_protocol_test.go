package realms

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/p2p"
)

// testNetworks returns Networks whose dials can be told apart by route.
func testNetworks() Networks {
	return Networks{
		RakNet:     minecraft.RakNet{ServerID: 7},
		HTTPClient: &http.Client{},
		DialSignaling: func(_ context.Context, connectionType int) (minecraft.SignalingConn, error) {
			return nil, &signalingError{connectionType}
		},
	}
}

// signalingError records the connection type a dial asked DialSignaling for.
type signalingError struct{ connectionType int }

func (e *signalingError) Error() string { return "test signaling" }

// route names how network dials: "raknet", "http", or the p2p connection type its signaling opens.
func route(t *testing.T, n Networks, network minecraft.Network) string {
	t.Helper()
	switch network := network.(type) {
	case minecraft.RakNet:
		if network.ServerID != n.RakNet.ServerID {
			t.Fatalf("RakNet = %#v, want the caller's", network)
		}
		return "raknet"
	case minecraft.NetherNetHTTP:
		if network.URL != "" || network.HTTPClient != n.HTTPClient {
			t.Fatalf("NetherNetHTTP = %#v, want no URL and the caller's HTTP client", network)
		}
		return "http"
	case minecraft.NetherNet:
		var signaling *signalingError
		if _, err := network.DialSignaling(t.Context(), "unused"); !errors.As(err, &signaling) {
			t.Fatalf("DialSignaling error = %v, want the caller's", err)
		}
		switch signaling.connectionType {
		case p2p.ConnectionTypeSignalingOverWebSocket:
			return "websocket"
		case p2p.ConnectionTypeSignalingOverJSONRPC:
			return "jsonrpc"
		}
		t.Fatalf("signaling opened connection type %d", signaling.connectionType)
	}
	t.Fatalf("network %T", network)
	return ""
}

// TestNetworksNetwork pins each service's route per protocol: the services differ only on NETHERNET.
func TestNetworksNetwork(t *testing.T) {
	const (
		hostPort = "play.example.com:19132"
		id       = "550e8400-e29b-41d4-a716-446655440000"
	)
	tests := []struct {
		name        string
		service     Service
		protocol    NetworkProtocol
		hostPort    string
		id          string
		wantRoute   string
		wantAddress string
	}{
		{name: "Realms DEFAULT", service: ServiceRealms, protocol: "DEFAULT", hostPort: hostPort, id: id, wantRoute: "raknet", wantAddress: hostPort},
		{name: "Realms missing protocol", service: ServiceRealms, hostPort: hostPort, wantRoute: "raknet", wantAddress: hostPort},
		{name: "Realms NETHERNET", service: ServiceRealms, protocol: "NETHERNET", hostPort: hostPort, id: id, wantRoute: "websocket", wantAddress: id},
		{name: "Realms NETHERNET_JSONRPC", service: ServiceRealms, protocol: "NETHERNET_JSONRPC", hostPort: hostPort, id: id, wantRoute: "jsonrpc", wantAddress: id},
		{name: "Gatherings Default", service: ServiceGatherings, protocol: "Default", hostPort: hostPort, id: id, wantRoute: "raknet", wantAddress: hostPort},
		{name: "Gatherings missing protocol", service: ServiceGatherings, hostPort: hostPort, wantRoute: "raknet", wantAddress: hostPort},
		{name: "Gatherings NetherNet", service: ServiceGatherings, protocol: "NetherNet", hostPort: hostPort, id: id, wantRoute: "http", wantAddress: hostPort},
		{name: "Gatherings NetherNet_JsonRpc", service: ServiceGatherings, protocol: "NetherNet_JsonRpc", hostPort: hostPort, id: id, wantRoute: "jsonrpc", wantAddress: id},
		{name: "DEFAULT without port", service: ServiceRealms, protocol: "DEFAULT", hostPort: "play.example.com"},
		{name: "DEFAULT port zero", service: ServiceGatherings, protocol: "Default", hostPort: "play.example.com:0"},
		{name: "DEFAULT blank host", service: ServiceGatherings, protocol: "Default", hostPort: "   :19132"},
		{name: "HTTP NetherNet without host", service: ServiceGatherings, protocol: "NetherNet", hostPort: ":19132", id: id},
		{name: "WebSocket NetherNet without ID", service: ServiceRealms, protocol: "NETHERNET", hostPort: hostPort, id: " "},
		{name: "JSON-RPC without ID", service: ServiceGatherings, protocol: "NetherNet_JsonRpc", hostPort: hostPort},
		{name: "unknown service", protocol: "NETHERNET", hostPort: hostPort, id: id},
		{name: "unknown protocol", service: ServiceRealms, protocol: "QUIC", hostPort: hostPort, id: id},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			n := testNetworks()
			network, address, err := n.Network(test.service, test.protocol, test.hostPort, test.id)
			if test.wantRoute == "" {
				if err == nil {
					t.Fatalf("Network() = %T, %q, want an error", network, address)
				}
				return
			}
			if err != nil {
				t.Fatalf("Network(): %v", err)
			}
			if got := route(t, n, network); got != test.wantRoute || address != test.wantAddress {
				t.Fatalf("Network() = %s to %q, want %s to %q", got, address, test.wantRoute, test.wantAddress)
			}
		})
	}
}

// A NetherNet ID cannot be dialed without the caller's signaling.
func TestNetworksNetworkRequiresDialSignaling(t *testing.T) {
	if _, _, err := (Networks{}).Network(ServiceRealms, NetworkProtocolNetherNetJSONRPC, "", "550e8400-e29b-41d4-a716-446655440000"); err == nil {
		t.Fatal("Network() without DialSignaling succeeded")
	}
}

// A Realms join response carries one address that is host:port or a NetherNet ID, per protocol.
func TestRealmAddressNetwork(t *testing.T) {
	n := testNetworks()
	for address, want := range map[RealmAddress]string{
		{Address: "127.0.0.1:19132", NetworkProtocol: NetworkProtocolDefault}:                               "raknet",
		{Address: "550e8400-e29b-41d4-a716-446655440000", NetworkProtocol: NetworkProtocolNetherNetJSONRPC}: "jsonrpc",
		{Address: "12345678901234567890", NetworkProtocol: NetworkProtocolNetherNet}:                        "websocket",
	} {
		network, got, err := address.Network(n)
		if err != nil || got != address.Address || route(t, n, network) != want {
			t.Fatalf("%+v: Network() = %T, %q, %v; want %s to the address", address, network, got, err, want)
		}
	}
}
