package p2p

import "github.com/sandertv/gophertunnel/minecraft/realms"

// ConnectionTypeFromRealmProtocol maps a Realms network protocol to the P2P
// signaling connection type used to dial the advertised NetherNet address.
func ConnectionTypeFromRealmProtocol(protocol realms.NetworkProtocol) (int, bool) {
	switch realms.ParseNetworkProtocol(string(protocol)) {
	case realms.NetworkProtocolNetherNet:
		return ConnectionTypeSignalingOverWebSocket, true
	case realms.NetworkProtocolNetherNetJSONRPC:
		return ConnectionTypeSignalingOverJSONRPC, true
	default:
		return 0, false
	}
}
