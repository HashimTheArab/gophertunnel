package minecraft

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/endpoint"
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
type NetherNet struct {
	// Signaling is the interface used to exchange connection details with the remote peers.
	// When nil, dials without DialSignaling and pings use a new [endpoint.Client], and Listen serves an
	// [endpoint.Handler] on its address. A Client cannot listen and a Handler cannot dial or ping.
	Signaling nethernet.Signaling
	// DialSignaling optionally opens a fresh signaling connection for each outbound dial.
	// NetherNet owns the returned signaling connection: it closes it when the resulting
	// transport connection closes, or after a failed dial once the dialer's terminal
	// error signal has had time to complete.
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
	// signalingCloseDelay shortens the failed-dial signaling close delay in tests.
	signalingCloseDelay time.Duration
}

// Ensure the connection returned by NetherNet.DialContext has the optional
// packet methods used by Encoder and Decoder, even though DialContext returns it
// as a net.Conn.
var _ packet.TransportCapabilities = (*nethernet.Conn)(nil)

// DialContext establishes a connection with the remote NetherNet network using the address.
func (n NetherNet) DialContext(ctx context.Context, address string) (net.Conn, error) {
	return n.dialContext(ctx, address, nil)
}

// DialContextIdentity establishes a connection with a preconfigured [nethernet.Dialer.Identity].
// Call [NetherNet.DialContextIdentityProvider] when the identity has not already been configured.
func (n NetherNet) DialContextIdentity(ctx context.Context, address, token string, privateKey *ecdsa.PrivateKey) (net.Conn, error) {
	if n.Dialer.Identity == nil || n.Dialer.Identity.Domain == "" {
		return nil, errors.New("minecraft: NetherNet.DialContextIdentity: identity provider is empty")
	}
	return n.dialContext(ctx, address, &nethernet.Identity{
		PrivateKey: privateKey,
		Token:      token,
		Domain:     n.Dialer.Identity.Domain,
	})
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
	var owned SignalingConn
	if n.DialSignaling != nil {
		conn, err := n.DialSignaling(ctx, address)
		if err != nil {
			return nil, err
		}
		if conn == nil {
			return nil, errors.New("minecraft: NetherNet.DialContext: DialSignaling returned nil")
		}
		signaling, owned = conn, conn
	}
	if signaling == nil {
		signaling = endpoint.NewClient()
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
		if owned != nil {
			// The dialer may still be sending its terminal error signal asynchronously;
			// give it time to complete before closing the signaling under it.
			delay := n.signalingCloseDelay
			if delay == 0 {
				delay = nethernet.SignalErrorTimeout + time.Second
			}
			time.AfterFunc(delay, func() { _ = owned.Close() })
		}
		return nil, err
	}
	if conn == nil {
		if owned != nil {
			_ = owned.Close()
		}
		return nil, errors.New("minecraft: NetherNet.DialContext: dial returned nil connection")
	}
	if owned != nil {
		// A NetherNet connection ends its context when it closes or fails, and parents
		// everything it signals on that context, so closing signaling then cannot race.
		c, ok := conn.(interface{ Context() context.Context })
		if !ok {
			_ = conn.Close()
			_ = owned.Close()
			return nil, errors.New("minecraft: NetherNet.DialContext: dialed connection has no context to release signaling with")
		}
		go func() {
			<-c.Context().Done()
			_ = owned.Close()
		}()
	}
	return conn, nil
}

// PingContext sends a ping to the specified address if the [NetherNet.Signaling]
// supports sending a ping request to the remote server. Otherwise, it returns an error.
// If [NetherNet.Signaling] is nil, [endpoint.Client] will be created and used instead.
// The address must be an HTTP/HTTPS URL with a port.
func (n NetherNet) PingContext(ctx context.Context, address string) ([]byte, error) {
	if n.Signaling == nil {
		n.Signaling = endpoint.NewClient()
	}
	if p, ok := n.Signaling.(pinger); ok {
		return p.PingContext(ctx, address)
	}
	return nil, errors.New("minecraft: NetherNet.PingContext: not supported")
}

// Ensure that the default Signaling Client implementation used by NetherNet satisfies
// the pinger interface.
var _ pinger = (*endpoint.Client)(nil)

// pinger is implemented by [nethernet.Signaling] that support sending
// ping requests to remote servers.
type pinger interface {
	PingContext(ctx context.Context, address string) ([]byte, error)
}

// Listen creates a NetherNet listener using the [NetherNet.Signaling] implementation.
// If [NetherNet.Signaling] is nil, an HTTP server will be started at the specified address.
// Unlike [PingContext] and [DialContext], the address should be formatted as 'ip:port'.
func (n NetherNet) Listen(address string) (_ NetworkListener, err error) {
	var closeFunc func() error
	if n.Signaling == nil {
		server, err := endpoint.Serve(address)
		if err != nil {
			return nil, fmt.Errorf("serve HTTP: %w", err)
		}
		n.Signaling = server
		closeFunc = server.Close
	}
	if n.ListenConfig.Log == nil && n.Log != nil {
		n.ListenConfig.Log = n.Log
	}
	l, err := n.ListenConfig.Listen(n.Signaling)
	if err != nil {
		if closeFunc != nil {
			if err2 := closeFunc(); err2 != nil {
				err = errors.Join(err, fmt.Errorf("close HTTP server: %w", err2))
			}
		}
		return nil, err
	}
	return netherNetListener{NetworkListener: l, close: closeFunc}, nil
}

// netherNetListener implements [NetworkListener] with additional handling
// to close the HTTP server together with the underlying NetworkListener.
type netherNetListener struct {
	NetworkListener
	// close is a function for closing the HTTP server used to listen.
	// It is only set if the caller did not specify [NetherNet.Signaling]
	// when calling [NetherNet.Listen].
	close func() error
}

// Close closes the underlying NetworkListener along with the HTTP server.
func (n netherNetListener) Close() (err error) {
	if err2 := n.NetworkListener.Close(); err2 != nil {
		err = errors.Join(err, err2)
	}
	if n.close != nil {
		if err2 := n.close(); err2 != nil {
			err = errors.Join(err, fmt.Errorf("close HTTP server: %w", err2))
		}
	}
	return err
}

// init registers the NetherNet network.
func init() {
	RegisterNetwork("nethernet", func(l *slog.Logger) Network {
		return NetherNet{Log: l}
	})
}
