package minecraft

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"io"
	"log/slog"
	"net"

	"github.com/df-mc/go-nethernet"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// SignalingConn is a NetherNet signaling connection with a lifecycle that may be
// tied to a transport connection returned by [NetherNet.DialContext].
type SignalingConn interface {
	nethernet.Signaling
	io.Closer
}

// DialSignalingFunc opens signaling for one outbound NetherNet connection.
// The address is the remote NetherNet network ID passed to [NetherNet.DialContext].
type DialSignalingFunc func(ctx context.Context, address string) (SignalingConn, error)

// NetherNet is an implementation of a NetherNet network, a WebRTC-based transport layer protocol.
// Signaling or DialSignaling must be provided before dialing; listening requires Signaling.
type NetherNet struct {
	// Signaling is the interface used to exchange connection details with the remote peers.
	// It is used for listening and for dialing when DialSignaling is nil.
	Signaling nethernet.Signaling
	// DialSignaling optionally opens a fresh signaling connection for each outbound dial.
	// NetherNet owns the returned signaling connection: it closes it when dialing fails or
	// when the resulting transport connection closes.
	DialSignaling DialSignalingFunc

	// Dialer specifies options for establishing a connection with DialContext.
	// Authenticated Minecraft dials replace Dialer.Identity with the identity built
	// from the verified multiplayer token, its issuer and the connection key.
	Dialer nethernet.Dialer
	// ListenConfig specifies options for listening for connections with Listen.
	ListenConfig nethernet.ListenConfig
	// Log is the logger used by default for Dialer and ListenConfig.
	// It is useful when registering this network from RegisterNetwork.
	Log *slog.Logger

	// dial replaces the low-level NetherNet dial in tests.
	dial func(context.Context, string, nethernet.Signaling, nethernet.Dialer) (net.Conn, error)
}

// Ensure the connection returned by NetherNet.DialContext has the optional
// packet methods used by Encoder and Decoder, even though DialContext returns it
// as a net.Conn.
var _ packet.TransportCapabilities = (*nethernet.Conn)(nil)

// DialContext ...
func (n NetherNet) DialContext(ctx context.Context, address string) (net.Conn, error) {
	return n.dialContext(ctx, address, nil)
}

// DialContextIdentity establishes a connection with a preconfigured [nethernet.Dialer.Identity].
// Call [NetherNet.DialContextIdentityProvider] when the identity has not already been configured.
func (n NetherNet) DialContextIdentity(ctx context.Context, address string, _ string, _ *ecdsa.PrivateKey) (net.Conn, error) {
	if n.Dialer.Identity == nil || n.Dialer.Identity.Domain == "" {
		return nil, errors.New("minecraft: NetherNet.DialContextIdentity: identity provider is empty")
	}
	return n.dialContext(ctx, address, n.Dialer.Identity)
}

// DialContextIdentityProvider establishes a connection with the remote NetherNet peer using the
// JWT token issued by identityProvider and the private key bound to the Minecraft connection.
// The resulting identity replaces any identity preconfigured on [NetherNet.Dialer].
func (n NetherNet) DialContextIdentityProvider(ctx context.Context, address string, token string, privateKey *ecdsa.PrivateKey, identityProvider string) (net.Conn, error) {
	if identityProvider == "" {
		return nil, errors.New("minecraft: NetherNet.DialContextIdentityProvider: identity provider is empty")
	}
	return n.dialContext(ctx, address, &nethernet.Identity{
		PrivateKey: privateKey,
		Token:      token,
		Domain:     identityProvider,
	})
}

func (n NetherNet) dialContext(ctx context.Context, address string, identity *nethernet.Identity) (net.Conn, error) {
	signaling := n.Signaling
	if n.DialSignaling != nil {
		conn, err := n.DialSignaling(ctx, address)
		if err != nil {
			return nil, err
		}
		if conn == nil {
			return nil, errors.New("minecraft: NetherNet.DialContext: DialSignaling returned nil")
		}
		signaling = conn
		n.Dialer.OwnSignaling = true
	}
	if signaling == nil {
		return nil, errors.New("minecraft: NetherNet.DialContext: Signaling is nil")
	}
	if n.Dialer.Log == nil && n.Log != nil {
		n.Dialer.Log = n.Log
	}
	if identity != nil {
		n.Dialer.Identity = identity
	}
	dial := n.dial
	if dial == nil {
		dial = func(ctx context.Context, address string, signaling nethernet.Signaling, dialer nethernet.Dialer) (net.Conn, error) {
			return dialer.DialContext(ctx, address, signaling)
		}
	}
	conn, err := dial(ctx, address, signaling, n.Dialer)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("minecraft: NetherNet.DialContext: dial returned nil connection")
	}
	return conn, nil
}

// PingContext ...
func (n NetherNet) PingContext(context.Context, string) ([]byte, error) {
	return nil, errors.New("minecraft: NetherNet.PingContext: not supported")
}

// Listen ...
func (n NetherNet) Listen(string) (NetworkListener, error) {
	if n.Signaling == nil {
		return nil, errors.New("minecraft: NetherNet.Listen: Signaling is nil")
	}
	if n.ListenConfig.Log == nil && n.Log != nil {
		n.ListenConfig.Log = n.Log
	}
	return n.ListenConfig.Listen(n.Signaling)
}
