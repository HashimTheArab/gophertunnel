package realms

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/p2p"
)

// NetworkProtocol is the protocol a Realms or Gatherings join response names for reaching the server.
// The services spell it in different cases; compare values through ParseNetworkProtocol.
type NetworkProtocol string

const (
	NetworkProtocolDefault          NetworkProtocol = "DEFAULT"
	NetworkProtocolNetherNet        NetworkProtocol = "NETHERNET"
	NetworkProtocolNetherNetJSONRPC NetworkProtocol = "NETHERNET_JSONRPC"
)

// ParseNetworkProtocol converts a network protocol string to a NetworkProtocol value.
func ParseNetworkProtocol(protocol string) NetworkProtocol {
	return NetworkProtocol(strings.ToUpper(strings.TrimSpace(protocol)))
}

// Valid reports whether the protocol is one of the known constants.
func (p NetworkProtocol) Valid() bool {
	switch ParseNetworkProtocol(string(p)) {
	case NetworkProtocolDefault, NetworkProtocolNetherNet, NetworkProtocolNetherNetJSONRPC:
		return true
	default:
		return false
	}
}

// Service is a service that assigns servers by NetworkProtocol.
type Service uint8

const (
	ServiceRealms Service = iota + 1
	ServiceGatherings
)

// Networks holds the caller's transports that RealmAddress.Network and gatherings.Address.Network
// choose from.
type Networks struct {
	// RakNet dials DEFAULT addresses.
	RakNet minecraft.RakNet
	// NetherNet configures NetherNet dials; each address replaces its signaling with the one it needs.
	NetherNet minecraft.NetherNet
	// HTTPClient sends HTTP signaling requests; nil uses http.DefaultTransport.
	HTTPClient *http.Client
	// DialSignaling opens Xbox signaling of a p2p connection type for one dial, such as
	// p2p.DialClientSignaling with the caller's token source. Without it, NetherNet IDs cannot be dialed.
	DialSignaling func(ctx context.Context, connectionType int) (minecraft.SignalingConn, error)
}

// Network returns the network and address to pass to minecraft.Dialer.DialContextNetwork for a server
// s assigned with protocol, missing meaning DEFAULT. Only the address form the protocol uses is read:
//
//	protocol           Realms                       Gatherings
//	DEFAULT            RakNet to hostPort           RakNet to hostPort
//	NETHERNET          WebSocket signaling to id    HTTP signaling to hostPort, never RakNet
//	NETHERNET_JSONRPC  JSON-RPC signaling to id     JSON-RPC signaling to id
//
// A Gatherings NETHERNET assignment names no URL scheme, so the network asks HTTPS, then HTTP, as
// minecraft.ProbeNetherNet does.
func (n Networks) Network(s Service, protocol NetworkProtocol, hostPort, id string) (minecraft.Network, string, error) {
	switch p := ParseNetworkProtocol(string(protocol)); {
	case p == NetworkProtocolDefault || p == "":
		return hostPortNetwork(n.RakNet, hostPort)
	case p == NetworkProtocolNetherNet && s == ServiceRealms:
		return n.signaled(p2p.ConnectionTypeSignalingOverWebSocket, id)
	case p == NetworkProtocolNetherNet && s == ServiceGatherings:
		return hostPortNetwork(minecraft.NetherNetHTTP{NetherNet: n.NetherNet, HTTPClient: n.HTTPClient}, hostPort)
	case p == NetworkProtocolNetherNetJSONRPC:
		return n.signaled(p2p.ConnectionTypeSignalingOverJSONRPC, id)
	}
	return nil, "", fmt.Errorf("realms: unsupported network protocol %q for service %d", protocol, s)
}

// hostPortNetwork returns network with hostPort once it names both a host and a nonzero port.
func hostPortNetwork(network minecraft.Network, hostPort string) (minecraft.Network, string, error) {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil || strings.TrimSpace(host) == "" || strings.TrimLeft(port, "0") == "" {
		return nil, "", fmt.Errorf("realms: server address %q has no host or port", hostPort)
	}
	return network, hostPort, nil
}

// signaled returns NetherNet that reaches id through Xbox signaling of connectionType.
func (n Networks) signaled(connectionType int, id string) (minecraft.Network, string, error) {
	if strings.TrimSpace(id) == "" {
		return nil, "", errors.New("realms: server address has no NetherNet ID")
	}
	if n.DialSignaling == nil {
		return nil, "", errors.New("realms: Networks.DialSignaling is required to dial a NetherNet ID")
	}
	network := n.NetherNet
	network.Signaling = nil
	network.DialSignaling = func(ctx context.Context, _ string) (minecraft.SignalingConn, error) {
		return n.DialSignaling(ctx, connectionType)
	}
	return network, id, nil
}
