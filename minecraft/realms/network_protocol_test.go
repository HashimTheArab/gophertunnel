package realms

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"testing"

	"github.com/df-mc/go-nethernet"
	"github.com/sandertv/gophertunnel/minecraft"
)

// testNetworks returns Networks whose dials can be told apart by route.
func testNetworks() Networks {
	return Networks{
		RakNet:     minecraft.RakNet{ServerID: 7},
		NetherNet:  minecraft.NetherNet{Log: slog.New(slog.DiscardHandler), Dialer: nethernet.Dialer{AllowIdentitylessServer: true}},
		HTTPClient: &http.Client{},
		DialSignaling: func(context.Context) (minecraft.SignalingConn, error) {
			return nil, errTestSignaling
		},
	}
}

// errTestSignaling is returned by the DialSignaling of testNetworks.
var errTestSignaling = errors.New("test signaling")

// route names how network dials: "raknet", "http", or "jsonrpc" when it opens the caller's signaling.
// It fails the test when the caller's settings did not reach the network.
func route(t *testing.T, n Networks, network minecraft.Network) string {
	t.Helper()
	sameNetherNet := func(got minecraft.NetherNet) {
		if got.Log != n.NetherNet.Log || got.Dialer.AllowIdentitylessServer != n.NetherNet.Dialer.AllowIdentitylessServer {
			t.Fatalf("NetherNet = %#v, want the caller's settings", got)
		}
	}
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
		sameNetherNet(network.NetherNet)
		return "http"
	case minecraft.NetherNet:
		sameNetherNet(network)
		if _, err := network.DialSignaling(t.Context(), "unused"); !errors.Is(err, errTestSignaling) {
			t.Fatalf("DialSignaling error = %v, want the caller's", err)
		}
		return "jsonrpc"
	}
	t.Fatalf("network %T", network)
	return ""
}

const (
	testHost     = "play.example.com"
	testHostPort = testHost + ":19132"
	testID       = "550e8400-e29b-41d4-a716-446655440000"
)

// TestNetworksRealm pins that, as in vanilla, a realm is joined only over JSON-RPC signaling.
func TestNetworksRealm(t *testing.T) {
	tests := []struct {
		name      string
		protocol  NetworkProtocol
		address   string
		wantRoute string
	}{
		{name: "NETHERNET_JSONRPC", protocol: "NETHERNET_JSONRPC", address: testID, wantRoute: "jsonrpc"},
		{name: "NETHERNET_JSONRPC padded ID", protocol: "NETHERNET_JSONRPC", address: " " + testID + " ", wantRoute: "jsonrpc"},
		{name: "NETHERNET_JSONRPC without ID", protocol: "NETHERNET_JSONRPC", address: " "},
		{name: "legacy NETHERNET", protocol: "NETHERNET", address: testID},
		{name: "DEFAULT", protocol: "DEFAULT", address: testHostPort},
		{name: "missing protocol", address: testHostPort},
		{name: "unknown protocol", protocol: "QUIC", address: testHostPort},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			n := testNetworks()
			network, address, err := n.Realm(test.protocol, test.address)
			if test.wantRoute == "" {
				if err == nil {
					t.Fatalf("Realm() = %T, %q, want an error", network, address)
				}
				return
			}
			if err != nil {
				t.Fatalf("Realm(): %v", err)
			}
			if got := route(t, n, network); got != test.wantRoute || address != testID {
				t.Fatalf("Realm() = %s to %q, want %s to %q", got, address, test.wantRoute, testID)
			}
		})
	}
}

// TestNetworksExperience pins the route and address form each Gatherings protocol uses.
func TestNetworksExperience(t *testing.T) {
	tests := []struct {
		name        string
		protocol    NetworkProtocol
		host        string
		port        uint16
		id          string
		wantRoute   string
		wantAddress string
	}{
		{name: "Default", protocol: "Default", host: testHost, port: 19132, id: testID, wantRoute: "raknet", wantAddress: testHostPort},
		{name: "missing protocol", host: testHost, port: 19132, wantRoute: "raknet", wantAddress: testHostPort},
		{name: "IPv6 literal", protocol: "Default", host: "::1", port: 19132, wantRoute: "raknet", wantAddress: "[::1]:19132"},
		{name: "NetherNet", protocol: "NetherNet", host: testHost, port: 19132, id: testID, wantRoute: "http", wantAddress: testHostPort},
		{name: "NetherNet_JsonRpc", protocol: "NetherNet_JsonRpc", host: testHost, port: 19132, id: testID, wantRoute: "jsonrpc", wantAddress: testID},
		{name: "NetherNet_JsonRpc padded ID", protocol: "NetherNet_JsonRpc", id: "\t" + testID + " ", wantRoute: "jsonrpc", wantAddress: testID},
		{name: "Default port zero", protocol: "Default", host: testHost},
		{name: "Default blank host", protocol: "Default", host: "   ", port: 19132},
		{name: "NetherNet without host", protocol: "NetherNet", port: 19132, id: testID},
		{name: "NetherNet_JsonRpc without ID", protocol: "NetherNet_JsonRpc", host: testHost, port: 19132},
		{name: "unknown protocol", protocol: "QUIC", host: testHost, port: 19132, id: testID},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			n := testNetworks()
			network, address, err := n.Experience(test.protocol, test.host, test.port, test.id)
			if test.wantRoute == "" {
				if err == nil {
					t.Fatalf("Experience() = %T, %q, want an error", network, address)
				}
				return
			}
			if err != nil {
				t.Fatalf("Experience(): %v", err)
			}
			if got := route(t, n, network); got != test.wantRoute || address != test.wantAddress {
				t.Fatalf("Experience() = %s to %q, want %s to %q", got, address, test.wantRoute, test.wantAddress)
			}
		})
	}
}

// A NetherNet ID is dialed through the caller's JSON-RPC signaling, which it cannot do without.
func TestNetworksSignaled(t *testing.T) {
	n := testNetworks()
	network, address, err := n.signaled(testID)
	if err != nil || address != testID || route(t, n, network) != "jsonrpc" {
		t.Fatalf("signaled = %T, %q, %v; want jsonrpc to the ID", network, address, err)
	}
	if _, _, err := (Networks{}).signaled(testID); err == nil {
		t.Fatal("signaled without DialSignaling succeeded")
	}
}

// NetherNetID accepts exactly the realms Network can dial and returns the ID Network dials.
func TestRealmAddressNetherNetID(t *testing.T) {
	for _, protocol := range []NetworkProtocol{"NETHERNET_JSONRPC", "NETHERNET", "DEFAULT", "", "QUIC"} {
		for _, address := range []string{testID, " " + testID + " ", " "} {
			a := RealmAddress{Address: address, NetworkProtocol: protocol}
			_, wantID, wantErr := a.Network(testNetworks())
			id, err := a.NetherNetID()
			if (err != nil) != (wantErr != nil) || id != wantID {
				t.Fatalf("NetherNetID(%q, %q) = %q, %v; Network gives %q, %v", protocol, address, id, err, wantID, wantErr)
			}
		}
	}
}

// A Realms join response carries the NetherNet ID in its one address field.
func TestRealmAddressNetwork(t *testing.T) {
	n := testNetworks()
	network, address, err := RealmAddress{Address: testID, NetworkProtocol: NetworkProtocolNetherNetJSONRPC}.Network(n)
	if err != nil || address != testID || route(t, n, network) != "jsonrpc" {
		t.Fatalf("Network() = %T, %q, %v; want JSON-RPC signaling to the ID", network, address, err)
	}
	if _, _, err := (RealmAddress{Address: "127.0.0.1:19132", NetworkProtocol: NetworkProtocolDefault}).Network(n); err == nil {
		t.Fatal("Network() joined a DEFAULT realm over RakNet")
	}
}
