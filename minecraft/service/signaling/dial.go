package signaling

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"

	"github.com/coder/websocket"
	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-playfab"
	"github.com/sandertv/gophertunnel/minecraft/auth/xal"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/service"
	"golang.org/x/oauth2"
)

// Dialer provides methods and fields to establish a Conn to a signaling service.
// It allows specifying options for the connection and handles various authentication
// and environment configuration.
type Dialer struct {
	// Options specifies the options for dialing the signaling service over
	// a WebSocket connection. If nil, a new *websocket.DialOptions will be
	// created. Note that the [websocket.DialOptions.HTTPClient] and its Transport
	// will be overridden with a [service.Transport] for authorization.
	Options *websocket.DialOptions

	// NetworkID specifies a unique ID for the network. If zero, a random value will
	// be automatically set from [rand.Uint64]. It is included in the URI for establishing
	// a WebSocket connection.
	NetworkID uint64

	// Log is used to logging messages at various levels. If nil, the default
	// [slog.Logger] will be set from [slog.Default].
	Log *slog.Logger

	// HTTPClient is used to make HTTP requests to the signaling service. If nil, the default
	// [http.Client] will be used.
	HTTPClient *http.Client
}

// DialContext establishes a Conn to the signaling service using the [oauth2.TokenSource] for
// authentication and authorization with franchise services. It obtains the necessary [franchise.Discovery]
// and [Environment] needed, then calls DialWithIdentityAndEnvironment internally. It is the
// method that is typically used when no configuration of identity and environment is required.
func (d Dialer) DialContext(ctx context.Context, src oauth2.TokenSource) (*Conn, error) {
	if d.HTTPClient != nil {
		if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); !ok || c == nil {
			ctx = context.WithValue(ctx, oauth2.HTTPClient, d.HTTPClient)
		}
	}

	discovery, err := service.Discover(ctx, service.ApplicationTypeMinecraftPE, protocol.CurrentVersion)
	if err != nil {
		return nil, fmt.Errorf("obtain discovery: %w", err)
	}
	a := new(service.AuthorizationEnvironment)
	if err := discovery.Environment(a); err != nil {
		return nil, fmt.Errorf("obtain environment for %s: %w", a.ServiceName(), err)
	}
	s := new(Environment)
	if err := discovery.Environment(s); err != nil {
		return nil, fmt.Errorf("obtain environment for %s: %w", s.ServiceName(), err)
	}

	return d.DialWithIdentityAndEnvironment(ctx, playfab.XBLIdentityProvider{
		TokenSource: xal.RefreshTokenSource(ctx, src, playfab.RelyingParty),
	}, s)
}

// DialWithIdentityAndEnvironment establishes a Conn to the signaling service using the [franchise.IdentityProvider]
// for authorization and the [Environment] for creating the URI of an internal WebSocket connection. It appends 'ws/v1.0/signaling'
// with the NetworkID to the service URI from the Environment. It sets up necessary options and logging if not provided, and
// dials a [websocket.Conn] using [websocket.Dial]. The [context.Context] may be used to cancel the connection if necessary as
// soon as possible.
func (d Dialer) DialWithIdentityAndEnvironment(ctx context.Context, i playfab.IdentityProvider, env *Environment) (*Conn, error) {
	// DialWithIdentityAndEnvironment may be called directly (without DialContext). Ensure the ctx has an HTTP
	// client for any discovery/auth HTTP requests, without affecting the websocket dial client.
	if d.HTTPClient != nil {
		if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); !ok || c == nil {
			ctx = context.WithValue(ctx, oauth2.HTTPClient, d.HTTPClient)
		}
	}

	if d.Options == nil {
		d.Options = &websocket.DialOptions{}
	}
	if d.Options.HTTPClient == nil {
		d.Options.HTTPClient = &http.Client{}
	}
	if d.NetworkID == 0 {
		d.NetworkID = rand.Uint64()
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}

	var (
		hasTransport bool
		base         = d.Options.HTTPClient.Transport
	)
	if base != nil {
		_, hasTransport = base.(*service.Transport)
	}
	if !hasTransport {
		d.Options.HTTPClient.Transport = &service.Transport{
			IdentityProvider: i,
			Base:             base,
		}
	}

	u, err := url.Parse(env.ServiceURI)
	if err != nil {
		return nil, fmt.Errorf("parse service URI: %w", err)
	}

	c, _, err := websocket.Dial(ctx, u.JoinPath("/ws/v1.0/signaling", strconv.FormatUint(d.NetworkID, 10)).String(), d.Options)
	if err != nil {
		return nil, err
	}

	conn := &Conn{
		conn: c,
		d:    d,

		credentialsReceived: make(chan struct{}),

		closed: make(chan struct{}),

		notifiers: make(map[uint32]chan<- *nethernet.Signal),
	}
	conn.ctx, conn.cancel = context.WithCancelCause(context.Background())
	go conn.read()

	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-conn.credentialsReceived:
		return conn, nil
	}
}
