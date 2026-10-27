package minecraft

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

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

// DialContext ...
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

// NetherNetServerIdentity returns a nethernet.ListenConfig.IssueServerIdentity backed by the P-384
// key saved at path, creating it on first use. Clients trust plain-HTTP servers on first use by key,
// so a key that survives restarts is only ever confirmed once.
func NetherNetServerIdentity(path string) (func(context.Context) (*nethernet.Identity, error), error) {
	key, err := loadOrCreateNetherNetKey(path)
	if err != nil {
		return nil, fmt.Errorf("minecraft: NetherNet server key: %w", err)
	}
	return func(context.Context) (*nethernet.Identity, error) {
		// "self" is the domain Bedrock Dedicated Server presents.
		return nethernet.GenerateServerIdentity(key, "self")
	}, nil
}

// loadOrCreateNetherNetKey reads the PEM key at path, or generates and saves one when the file does
// not exist. A file that exists but cannot be read as a P-384 key is an error, never replaced.
func loadOrCreateNetherNetKey(path string) (*ecdsa.PrivateKey, error) {
	if key, err := readNetherNetKey(path); !errors.Is(err, fs.ErrNotExist) {
		return key, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		// Another process created the key first; use that one.
		return readNetherNetKey(path)
	} else if err != nil {
		return nil, err
	}
	if err := pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	return key, nil
}

// readNetherNetKey parses a P-384 key from a SEC 1 or PKCS #8 PEM file.
func readNetherNetKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	var key *ecdsa.PrivateKey
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var parsed any
		if parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			var ok bool
			if key, ok = parsed.(*ecdsa.PrivateKey); !ok {
				err = fmt.Errorf("%s: %T is not an ECDSA key", path, parsed)
			}
		}
	default:
		err = fmt.Errorf("%s: unexpected PEM block %q", path, block.Type)
	}
	if err != nil {
		return nil, err
	}
	if key.Curve != elliptic.P384() {
		return nil, fmt.Errorf("%s: key is not P-384", path)
	}
	return key, nil
}
