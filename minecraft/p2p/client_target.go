package p2p

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"

	"github.com/df-mc/go-nethernet"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/service"
	"github.com/sandertv/gophertunnel/minecraft/service/signaling"
	"github.com/sandertv/gophertunnel/minecraft/service/signaling/messaging"
)

// SignalingConn is a client-side NetherNet signaling connection with an owned lifetime.
type SignalingConn interface {
	nethernet.Signaling
	io.Closer
}

// ClientSignalingOptions configures an outbound signaling connection. Local NetherNet identity is intentionally not
// configurable here: client dials generate their own identity, while host-advertised IDs remain remote metadata.
type ClientSignalingOptions struct {
	HTTPClient *http.Client
	Log        *slog.Logger

	// JSONRPCDial replaces the Player Messaging signaling dial in tests or custom clients.
	JSONRPCDial func(context.Context, service.TokenSource, ClientSignalingOptions) (SignalingConn, error)
	// WebSocketDial replaces the direct WebSocket signaling dial in tests or custom clients.
	WebSocketDial func(context.Context, service.TokenSource, ClientSignalingOptions) (SignalingConn, error)
}

// ClientTarget binds a joined friend-world session to its remote dial metadata and per-player login nonce.
type ClientTarget struct {
	lease      *clientTargetLease
	connection Connection
	nonce      string
}

type clientTargetLease struct {
	session ClientSession
	mu      sync.Mutex
	closed  bool
}

// ClientSession is a joined friend-world session that supplies outbound connection metadata and a login nonce.
type ClientSession interface {
	Connection() Connection
	Nonce() string
	Close() error
}

// ClientTarget returns the outbound client target represented by the joined session.
func (s *Session) ClientTarget() (ClientTarget, error) {
	return ClientTargetFromSession(s)
}

// ClientTargetFromSession returns the outbound client target represented by a joined session.
func ClientTargetFromSession(s ClientSession) (ClientTarget, error) {
	if s == nil {
		return ClientTarget{}, errors.New("minecraft/p2p: session is nil")
	}
	connection := s.Connection()
	if err := connection.Validate(); err != nil {
		return ClientTarget{}, fmt.Errorf("minecraft/p2p: invalid joined connection: %w", err)
	}
	nonce := s.Nonce()
	if nonce == "" {
		return ClientTarget{}, errors.New("minecraft/p2p: joined session has no nonce")
	}
	return ClientTarget{lease: &clientTargetLease{session: s}, connection: connection, nonce: nonce}, nil
}

// DialAddress returns the remote address used by the selected connection type.
func (t ClientTarget) DialAddress() string {
	return t.connection.Address()
}

// ConnectionType returns the host-advertised signaling connection type.
func (t ClientTarget) ConnectionType() int {
	return t.connection.Type
}

// ApplyClientData applies the host-issued nonce required for the joined player's Minecraft login.
func (t ClientTarget) ApplyClientData(data *login.ClientData) {
	if data == nil {
		return
	}
	data.Nonce = t.nonce
}

// DialSignaling opens the outbound signaling connection selected by the joined target.
func (t ClientTarget) DialSignaling(ctx context.Context, src service.TokenSource, opts ClientSignalingOptions) (SignalingConn, error) {
	return DialClientSignaling(ctx, t.connection.Type, src, opts)
}

// Close leaves the joined friend-world session. It is safe to call more than once and on copied targets.
func (t ClientTarget) Close() error {
	if t.lease == nil || t.lease.session == nil {
		return nil
	}
	t.lease.mu.Lock()
	defer t.lease.mu.Unlock()
	if t.lease.closed {
		return nil
	}
	if err := t.lease.session.Close(); err != nil {
		return err
	}
	t.lease.closed = true
	return nil
}

// DialClientSignaling opens client-side signaling for a resolved NetherNet connection type.
func DialClientSignaling(ctx context.Context, connectionType int, src service.TokenSource, opts ClientSignalingOptions) (SignalingConn, error) {
	switch connectionType {
	case ConnectionTypeSignalingOverJSONRPC:
		if opts.JSONRPCDial != nil {
			return opts.JSONRPCDial(ctx, src, opts)
		}
		conn, err := (messaging.Dialer{HTTPClient: opts.HTTPClient, Log: opts.Log}).DialContext(ctx, src)
		if err != nil {
			return nil, err
		}
		return conn, nil
	case ConnectionTypeSignalingOverWebSocket:
		if opts.WebSocketDial != nil {
			return opts.WebSocketDial(ctx, src, opts)
		}
		conn, err := (signaling.Dialer{HTTPClient: opts.HTTPClient, Log: opts.Log}).DialContext(ctx, src)
		if err != nil {
			return nil, err
		}
		return conn, nil
	default:
		return nil, fmt.Errorf("minecraft/p2p: unsupported client signaling connection type: %d", connectionType)
	}
}
