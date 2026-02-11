package messaging

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"

	"github.com/coder/websocket"
	"github.com/creachadair/jrpc2"
	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-playfab"
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/auth/xal"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/service"
	"github.com/sandertv/gophertunnel/minecraft/service/signaling"
	"golang.org/x/oauth2"
)

// Dialer establishes a JSON-RPC messaging connection implementing nethernet.Signaling.
type Dialer struct {
	// Options specifies websocket dial options. If nil, defaults are used.
	// The HTTP transport will be wrapped with service.Transport for authentication.
	Options *websocket.DialOptions

	// NetworkID is the local NetherNet ID. If zero, a random one is generated.
	NetworkID uint64

	// Log is used for diagnostic logs. If nil, slog.Default() is used.
	Log *slog.Logger

	// HTTPClient is used for discovery/auth requests when dialing.
	HTTPClient *http.Client
}

// DialContext discovers service environments and dials using a token source.
func (d Dialer) DialContext(ctx context.Context, src oauth2.TokenSource) (*Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if d.HTTPClient != nil {
		if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); !ok || c == nil {
			ctx = context.WithValue(ctx, oauth2.HTTPClient, d.HTTPClient)
		}
	}

	discovery, err := service.Discover(ctx, service.ApplicationTypeMinecraftPE, protocol.CurrentVersion)
	if err != nil {
		return nil, fmt.Errorf("obtain discovery: %w", err)
	}

	env := new(signaling.Environment)
	if err := discovery.Environment(env); err != nil {
		return nil, fmt.Errorf("obtain environment for %s: %w", env.ServiceName(), err)
	}

	return d.DialWithIdentityAndEnvironment(ctx, playfab.XBLIdentityProvider{
		TokenSource: xal.RefreshTokenSource(ctx, src, playfab.RelyingParty),
	}, env)
}

// DialWithIdentityAndEnvironment dials the messaging websocket using the provided identity provider.
func (d Dialer) DialWithIdentityAndEnvironment(ctx context.Context, i playfab.IdentityProvider, env *signaling.Environment) (*Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if env == nil {
		return nil, errors.New("minecraft/service/messaging: DialWithIdentityAndEnvironment: environment is nil")
	}

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

	c, _, err := websocket.Dial(ctx, u.JoinPath("/ws/v1.0/messaging/connect").String(), d.Options)
	if err != nil {
		return nil, err
	}

	conn := &Conn{
		log:            d.Log,
		conn:           c,
		localNetworkID: d.NetworkID,
		notifiers:      make(map[int]chan<- *nethernet.Signal),
		expected:       make(map[uuid.UUID]chan<- error),
	}
	conn.ctx, conn.cancel = context.WithCancelCause(context.Background())
	conn.client = jrpc2.NewClient(&websocketChannel{c}, &jrpc2.ClientOptions{
		OnCallback: conn.handleCallback,
		OnStop: func(_ *jrpc2.Client, err error) {
			conn.cancel(err)
			_ = conn.Close()
		},
	})

	go conn.background()
	return conn, nil
}
