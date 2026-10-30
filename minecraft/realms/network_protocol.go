package realms

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/p2p"
)

// NetworkProtocol is the protocol a Realms or Gatherings join response names for reaching the server.
// The services spell it in different cases; compare values through ParseNetworkProtocol. Realms and
// Gatherings read the same value differently; Networks documents what each one means.
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

// Networks holds the caller's transports for dialing a server a join response names. Realms and
// Gatherings read networkProtocol differently, as vanilla does:
//
//	protocol           Realm                         Experience
//	NETHERNET_JSONRPC  JSON-RPC signaling to the ID  JSON-RPC signaling to the ID
//	NETHERNET          error: legacy NetherNet       HTTP signaling to host:port, never RakNet
//	DEFAULT, missing   error: no RakNet              RakNet to host:port
type Networks struct {
	// RakNet dials experiences over RakNet.
	RakNet minecraft.RakNet
	// NetherNet configures NetherNet dials; each address replaces its signaling with the one it needs.
	NetherNet minecraft.NetherNet
	// HTTPClient sends HTTP signaling requests; nil uses http.DefaultTransport.
	HTTPClient *http.Client
	// DialSignaling opens Xbox signaling of a p2p connection type for one dial, such as
	// p2p.DialClientSignaling with the caller's token source. Without it, NetherNet IDs cannot be dialed.
	// Signaled only asks it for p2p.ConnectionTypeSignalingOverJSONRPC.
	DialSignaling func(ctx context.Context, connectionType int) (minecraft.SignalingConn, error)
}

// Realm returns the network and address to pass to minecraft.Dialer.DialContextNetwork for a realm
// whose join response names protocol and address.
func (n Networks) Realm(protocol NetworkProtocol, address string) (minecraft.Network, string, error) {
	switch ParseNetworkProtocol(string(protocol)) {
	case NetworkProtocolNetherNetJSONRPC:
		return n.Signaled(p2p.ConnectionTypeSignalingOverJSONRPC, address)
	case NetworkProtocolNetherNet:
		return nil, "", errors.New("realms: legacy NetherNet realms are no longer supported")
	default:
		return nil, "", fmt.Errorf("realms: RakNet is no longer supported in Realms (network protocol %q)", protocol)
	}
}

// Experience returns the network and address to pass to minecraft.Dialer.DialContextNetwork for an
// experience server, reading only the address form protocol uses. Vanilla builds no signaling URL for
// a NETHERNET assignment, so its host and port are probed, HTTPS first, as minecraft.ProbeNetherNet does.
func (n Networks) Experience(protocol NetworkProtocol, host string, port uint16, id string) (minecraft.Network, string, error) {
	switch ParseNetworkProtocol(string(protocol)) {
	case NetworkProtocolDefault, "":
		return hostPortNetwork(n.RakNet, host, port)
	case NetworkProtocolNetherNet:
		return hostPortNetwork(minecraft.NetherNetHTTP{NetherNet: n.NetherNet, HTTPClient: n.HTTPClient}, host, port)
	case NetworkProtocolNetherNetJSONRPC:
		return n.Signaled(p2p.ConnectionTypeSignalingOverJSONRPC, id)
	default:
		return nil, "", fmt.Errorf("realms: unsupported experience network protocol %q", protocol)
	}
}

// hostPortNetwork returns network with host:port once host is not blank and port is not zero.
func hostPortNetwork(network minecraft.Network, host string, port uint16) (minecraft.Network, string, error) {
	if strings.TrimSpace(host) == "" || port == 0 {
		return nil, "", fmt.Errorf("realms: server address %q:%d has no host or port", host, port)
	}
	return network, net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// Signaled returns NetherNet that reaches the NetherNet ID id through Xbox signaling of connectionType,
// which must be p2p.ConnectionTypeSignalingOverJSONRPC.
func (n Networks) Signaled(connectionType int, id string) (minecraft.Network, string, error) {
	if connectionType != p2p.ConnectionTypeSignalingOverJSONRPC {
		return nil, "", fmt.Errorf("realms: unsupported signaling connection type %d", connectionType)
	}
	if id = strings.TrimSpace(id); id == "" {
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
