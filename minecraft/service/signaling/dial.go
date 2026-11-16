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
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/service"
	"golang.org/x/oauth2"
)

// Dialer specifies options for connecting to the signaling service.
type Dialer struct {
	// Environment is the environment used for connecting to the signaling service. If nil, it is resolved
	// from [service.Default] as vanilla does: the 'signaling-afd' configuration, falling back to the
	// discovered 'signaling' service when that fails.
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
		if discovery.Environment(&direct) == nil && direct.ServiceURI != nil && direct.ServiceURI.Host != "" {
			p.fallback = direct.ServiceURI
		}
		if p.afd == nil && p.fallback == nil {
			return nil, fmt.Errorf("resolve signaling environment: discovery lists neither signaling-afd nor signaling: %w", afdErr)
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

	conn := newConn(d, &websocketChannel{c}, token.Claims.PlayerMessagingID)
	conn.conn = c
	go conn.ping(cfg.PingFrequency)
	conn.refreshCredentials()
	return conn, nil
}

// newConn returns a Conn exchanging messages over ch and handling the service's requests.
func newConn(d Dialer, ch channel.Channel, pmid uuid.UUID) *Conn {
	conn := &Conn{
		d:    d,
		pmid: pmid,

		notifiers: make(map[uint32]nethernet.Notifier),
		pending:   newPendingMap(),

		requests: make(chan serverRequest, requestQueueSize),
		sendRaw:  ch.Send,
	}
	conn.ctx, conn.cancel = context.WithCancelCause(context.Background())
	conn.client = jrpc2.NewClient(requestChannel{Channel: ch, conn: conn}, &jrpc2.ClientOptions{
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
	return conn
}

// websocketChannel is an implementation of [channel.Channel] over [websocket.Conn].
type websocketChannel struct{ *websocket.Conn }

// writeTimeout bounds one WebSocket write; a write that stalls this long closes the connection.
const writeTimeout = 15 * time.Second

// Send writes the provided bytes to the WebSocket connection.
func (ch *websocketChannel) Send(b []byte) error {
	// jrpc2 holds its client lock while sending, so a stalled write must not block Close forever.
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	return ch.Write(ctx, websocket.MessageText, b)
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

// requestChannel reads a Conn's connection leniently, as vanilla does, and hands the service's requests to
// the Conn in arrival order. Only replies to the client's own calls reach jrpc2; other objects are skipped.
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
		objects, batch, changed, ok := jsonRPCObjects(msg)
		if !ok {
			ch.conn.d.Log.Debug("skipping signaling frame that is not a JSON-RPC message", slog.Int("size", len(msg)))
			continue
		}
		replies := objects[:0]
		for _, m := range objects {
			r, ok := serverRequestOf(m)
			if !ok {
				if _, result := m["result"]; result || failed(m) {
					replies = append(replies, m)
				} else {
					changed = true // neither a request nor a reply
				}
				continue
			}
			changed = true
			select {
			case ch.conn.requests <- r:
			case <-ch.conn.ctx.Done():
				return nil, net.ErrClosed
			}
		}
		if len(replies) == 0 {
			continue
		}
		if !changed {
			return msg, nil
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

// serverRequestOf returns m as a request from the service. Like jrpc2, it treats m as a request only if it
// has a method and neither a result nor an error.
func serverRequestOf(m map[string]json.RawMessage) (serverRequest, bool) {
	var r serverRequest
	_, result := m["result"]
	if result || failed(m) || json.Unmarshal(m["method"], &r.method) != nil || r.method == "" {
		return r, false
	}
	r.id, r.params = m["id"], m["params"]
	if string(bytes.TrimSpace(r.id)) == "null" {
		r.id = nil
	}
	return r, true
}

// failed reports whether m carries a JSON-RPC error; an "error" member set to null carries none.
func failed(m map[string]json.RawMessage) bool {
	return m["error"] != nil && string(bytes.TrimSpace(m["error"])) != "null"
}

// jsonRPCObjects decodes a JSON-RPC object or batch without the top-level members JSON-RPC does not define.
// It skips batch elements that are not objects, reports whether anything was removed, and reports false if
// msg holds no object at all.
func jsonRPCObjects(msg []byte) (objects []map[string]json.RawMessage, batch, changed, ok bool) {
	trimmed := bytes.TrimSpace(msg)
	elements := []json.RawMessage{trimmed}
	if batch = len(trimmed) > 0 && trimmed[0] == '['; batch {
		if json.Unmarshal(trimmed, &elements) != nil {
			return nil, false, false, false
		}
	}
	for _, e := range elements {
		var m map[string]json.RawMessage
		if json.Unmarshal(e, &m) != nil || m == nil {
			changed = true
			continue
		}
		changed = dropUnknownMembers(m) || changed
		objects = append(objects, m)
	}
	return objects, batch, changed, len(objects) > 0
}

// dropUnknownMembers deletes the members of m JSON-RPC does not define and reports whether it did.
func dropUnknownMembers(m map[string]json.RawMessage) bool {
	changed := false
	for key := range m {
		if !jsonRPCMember(key) {
			delete(m, key)
			changed = true
		}
	}
	return changed
}

// jsonRPCMember reports whether key is a top-level member of a JSON-RPC 2.0 request or response.
func jsonRPCMember(key string) bool {
	switch key {
	case "jsonrpc", "id", "method", "params", "result", "error":
		return true
	}
	return false
}
