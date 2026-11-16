// Package signaling implements [nethernet.Signaling] over the JSON-RPC signaling service that
// vanilla clients use to negotiate NetherNet connections with other players.
package signaling

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/coder/websocket"
	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"github.com/df-mc/go-nethernet"
	"github.com/sandertv/gophertunnel/minecraft/service"
	"golang.org/x/oauth2"
)

// Dialer specifies options for connecting to the signaling service.
type Dialer struct {
	// Environment is the environment used for connecting to the signaling service.
	// If nil, it will be derived from [service.Default].
	Environment ConfigurationProvider
	// HTTPClient is the HTTP client used for WebSocket handshake messages and [Environment] discovery.
	HTTPClient *http.Client
	// Log is the logger used to log messages at various levels.
	Log *slog.Logger
	// NetworkID specifies a unique ID for the NetherNet network. If zero, a random value will
	// be automatically set from [rand.Uint64]. When listening on peer-to-peer worlds, this value
	// must match the NetworkID advertised in [p2p.Connection.NetherNetID] in order to successfully
	// negotiate with vanilla clients.
	NetworkID string
	// IgnoreDeliveryNotification disables waiting for the DeliveryNotification
	// acknowledgement after sending a signal to a remote peer.
	//
	// By default, [Conn.Signal] blocks until the remote peer sends back a
	// DeliveryNotification message to confirm receipt. Enabling this field
	// causes Signal to return as soon as the signaling service accepts the
	// message, without waiting for acknowledgement by the remote peer.
	//
	// The vanilla client appears to be sending DeliveryNotification only for
	// telemetry so this field is unlikely to affect the actual WebRTC negotiation.
	//
	// It may be useful when interoperating with third-party implementations
	// that do not send DeliveryNotification.
	IgnoreDeliveryNotification bool
}

// Dial connects to the signaling service with a 15 seconds timeout.
func (d Dialer) Dial(src service.TokenSource) (*Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	return d.DialContext(ctx, src)
}

// DialContext connects to the signaling service using the provided [service.TokenSource] for authorization.
func (d Dialer) DialContext(ctx context.Context, src service.TokenSource) (*Conn, error) {
	if d.HTTPClient == nil {
		d.HTTPClient = http.DefaultClient
	}
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); !ok || c == nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, d.HTTPClient)
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Environment == nil {
		discovery, err := service.Default(ctx)
		if err != nil {
			return nil, fmt.Errorf("discover network services: %w", err)
		}
		p := discoveredConfiguration{afd: new(AFDEnvironment), log: d.Log}
		afdErr := discovery.Environment(p.afd)
		if afdErr != nil {
			p.afd = nil
		}
		var direct directEnvironment
		if discovery.Environment(&direct) == nil {
			p.fallback = direct.ServiceURI
		}
		if p.afd == nil && p.fallback == nil {
			return nil, fmt.Errorf("resolve signaling environment: %w", afdErr)
		}
		d.Environment = p
	}
	if d.NetworkID == "" {
		d.NetworkID = strconv.FormatUint(rand.Uint64(), 10)
	}

	cfg, err := d.Environment.Configuration(ctx, d.HTTPClient, src)
	if err != nil {
		return nil, fmt.Errorf("request configuration: %w", err)
	}
	token, err := src.ServiceToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("request service token: %w", err)
	}

	opts := &websocket.DialOptions{
		HTTPHeader: make(http.Header),
		HTTPClient: d.HTTPClient,
	}
	opts.HTTPHeader.Set("Authorization", token.AuthorizationHeader)
	requestURL := cfg.ServiceURI.JoinPath("/ws/v1.0/messaging/connect")
	c, resp, err := websocket.Dial(ctx, requestURL.String(), opts)
	if err != nil {
		return nil, err
	}
	d.Log.Info("connected to signaling service",
		slog.String("transport", "jsonrpc"),
		slog.String("service_version", resp.Header.Get("Service-Version")),
	)

	conn := &Conn{
		conn: c,
		d:    d,
		pmid: token.Claims.PlayerMessagingID,

		notifiers: make(map[uint32]nethernet.Notifier),
		pending:   newPendingMap(),

		requests: make(chan serverRequest, requestQueueSize),
	}
	conn.ctx, conn.cancel = context.WithCancelCause(context.Background())
	ws := &websocketChannel{c}
	conn.sendRaw = ws.Send
	conn.client = jrpc2.NewClient(requestChannel{Channel: ws, conn: conn}, &jrpc2.ClientOptions{
		Logger: func(text string) {
			d.Log.Debug(text, slog.String("src", "jrpc2"))
		},
		OnStop: func(_ *jrpc2.Client, err error) {
			if err == nil {
				err = net.ErrClosed
			}
			conn.stop(fmt.Errorf("jrpc2 client stopped: %w", err))
		},
	})
	go conn.handleRequests()
	go conn.ping(cfg.PingFrequency)
	conn.refreshCredentials()
	return conn, nil
}

// websocketChannel is an implementation of [channel.Channel] over [websocket.Conn].
type websocketChannel struct{ *websocket.Conn }

// Send writes the provided bytes to the WebSocket connection.
func (ch *websocketChannel) Send(b []byte) error {
	return ch.Write(context.Background(), websocket.MessageText, b)
}

// Recv blocks until a new data is received in the WebSocket connection
// and returns the payload.
func (ch *websocketChannel) Recv() ([]byte, error) {
	_, msg, err := ch.Read(context.Background())
	return msg, err
}

// Close closes the underlying WebSocket connection.
func (ch *websocketChannel) Close() error {
	return ch.Conn.Close(websocket.StatusNormalClosure, "")
}

// requestChannel is the channel a Conn's jrpc2 client reads. It reads leniently like vanilla, skipping
// frames that are not JSON-RPC and dropping members JSON-RPC does not define, which jrpc2 rejects. It hands
// the requests the service sends to the Conn in arrival order and passes only replies on to jrpc2.
type requestChannel struct {
	channel.Channel
	conn *Conn
}

// Recv returns the next frame holding replies to the client's own calls.
func (ch requestChannel) Recv() ([]byte, error) {
	for {
		msg, err := ch.Channel.Recv()
		if err != nil {
			return nil, err
		}
		objects, batch, ok := jsonRPCObjects(msg)
		if !ok {
			ch.conn.d.Log.Debug("skipping signaling frame that is not a JSON-RPC message", slog.Int("size", len(msg)))
			continue
		}
		replies := objects[:0]
		for _, m := range objects {
			method, ok := m["method"]
			if !ok {
				replies = append(replies, m)
				continue
			}
			r := serverRequest{id: m["id"], params: m["params"]}
			_ = json.Unmarshal(method, &r.method)
			if string(bytes.TrimSpace(r.id)) == "null" {
				r.id = nil
			}
			select {
			case ch.conn.requests <- r:
			case <-ch.conn.ctx.Done():
				return nil, net.ErrClosed
			}
		}
		if len(replies) == 0 {
			continue
		}
		var v any = replies
		if !batch {
			v = replies[0]
		}
		if b, err := json.Marshal(v); err == nil {
			return b, nil
		}
	}
}

// jsonRPCObjects decodes a JSON-RPC object or batch, dropping the top-level members JSON-RPC does not
// define. It reports whether msg was a batch, and false if msg is not an object or array of objects.
func jsonRPCObjects(msg []byte) (objects []map[string]json.RawMessage, batch, ok bool) {
	trimmed := bytes.TrimSpace(msg)
	if batch = len(trimmed) > 0 && trimmed[0] == '['; batch {
		if json.Unmarshal(trimmed, &objects) != nil || len(objects) == 0 {
			return nil, false, false
		}
	} else {
		var m map[string]json.RawMessage
		if json.Unmarshal(trimmed, &m) != nil {
			return nil, false, false
		}
		objects = []map[string]json.RawMessage{m}
	}
	for _, m := range objects {
		if m == nil {
			return nil, false, false
		}
		dropUnknownMembers(m)
	}
	return objects, batch, true
}

// dropUnknownMembers deletes the members of m JSON-RPC does not define.
func dropUnknownMembers(m map[string]json.RawMessage) {
	for key := range m {
		if !jsonRPCMember(key) {
			delete(m, key)
		}
	}
}

// jsonRPCMember reports whether key is a top-level member of a JSON-RPC 2.0 request or response.
func jsonRPCMember(key string) bool {
	switch key {
	case "jsonrpc", "id", "method", "params", "result", "error":
		return true
	}
	return false
}
