package signaling

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/df-mc/go-nethernet"
	"github.com/sandertv/gophertunnel/minecraft/service/internal"
)

// Conn implements a [nethernet.Signaling] over a WebSocket connection.
//
// A Conn may be established using the methods of Dialer with either
// a [franchise.IdentityProvider] and an [Environment] or an [oauth2.TokenSource]
// for authorization.
//
// A Conn can be utilized with [nethernet.ListenConfig.Listen] or [nethernet.Dialer.DialContext].
type Conn struct {
	conn *websocket.Conn
	d    Dialer

	credentials         atomic.Pointer[nethernet.Credentials]
	credentialsReceived chan struct{}

	ctx    context.Context
	cancel context.CancelCauseFunc

	once   sync.Once
	closed chan struct{}

	notifyCount uint32
	notifiers   map[uint32]chan<- *nethernet.Signal
	notifiersMu sync.Mutex
}

func (c *Conn) PongData(b []byte) {
	// NOOP
}

// Signal sends a [nethernet.Signal] to a network.
func (c *Conn) Signal(ctx context.Context, signal *nethernet.Signal) error {
	return c.write(ctx, Message{
		Type: MessageTypeSignal,
		To:   signal.NetworkID,
		Data: signal.String(),
	})
}

// Notify registers a channel to receive incoming signals.
//
// The returned stop function unregisters the channel and closes it. Callers must not close
// the channel themselves.
func (c *Conn) Notify(ch chan<- *nethernet.Signal) (stop func()) {
	c.notifiersMu.Lock()
	i := c.notifyCount
	c.notifiers[i] = ch
	c.notifyCount++
	c.notifiersMu.Unlock()

	return func() {
		c.notifiersMu.Lock()
		c.stop(i, ch)
		c.notifiersMu.Unlock()
	}
}

// stop stops notifying signals on the notifier with the corresponding ID.
func (c *Conn) stop(i uint32, ch chan<- *nethernet.Signal) {
	if _, ok := c.notifiers[i]; !ok {
		return
	}
	delete(c.notifiers, i)
	close(ch)
}

// Credentials blocks until [nethernet.Credentials] are received from the server or the [context.Context]
// is done. It returns a [nethernet.Credentials] or an error if the Conn is closed or the [context.Context]
// is canceled or exceeded a deadline.
func (c *Conn) Credentials(ctx context.Context) (*nethernet.Credentials, error) {
	if credentials := c.credentials.Load(); credentials != nil {
		return credentials, nil
	}
	select {
	case <-c.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-c.credentialsReceived:
		return c.credentials.Load(), nil
	}
}

// Context returns a context that is canceled with a cause when the Conn is closed or a fatal
// signaling error is encountered.
func (c *Conn) Context() context.Context {
	return c.ctx
}

// NetworkID returns the network ID of the Conn. It may be specified from [Dialer.NetworkID], otherwise a random
// value will be automatically set from [rand.Uint64] in set up during [Dialer.DialContext]. It is utilized by
// [nethernet.Listener] and [nethernet.Dialer] to obtain its local network ID to listen.
func (c *Conn) NetworkID() string {
	return strconv.FormatUint(c.d.NetworkID, 10)
}

// Close closes the Conn and unregisters any notifiers. It ensures that the Conn is closed only once.
func (c *Conn) Close() (err error) {
	c.once.Do(func() {
		c.notifiersMu.Lock()
		for i, ch := range c.notifiers {
			c.stop(i, ch)
		}
		clear(c.notifiers)
		c.notifiersMu.Unlock()

		c.cancel(net.ErrClosed)
		close(c.closed)
		err = c.conn.Close(websocket.StatusNormalClosure, "")
	})
	return err
}

// read continuously reads messages from the WebSocket connection and handles them.
// It also sends a Message of MessageTypePing at 15 seconds intervals to keep the
// Conn alive. It goes as a background goroutine of the Conn and handles different
// types of messages: credentials, signals, and errors. It closes the Conn if it
// encounters an error or when the Conn is closed.
func (c *Conn) read() {
	go func() {
		ticker := time.NewTicker(time.Second * 15)
		defer ticker.Stop()

		for {
			select {
			case <-c.closed:
				return
			case <-ticker.C:
				if err := c.write(context.Background(), Message{
					Type: MessageTypePing,
				}); err != nil {
					c.d.Log.Error("error writing ping", internal.ErrAttr(err))
					return
				}
			}
		}
	}()
	defer c.Close()

	for {
		var message Message
		if err := wsjson.Read(context.Background(), c.conn, &message); err != nil {
			c.cancel(err)
			return
		}
		switch message.Type {
		case MessageTypeCredentials:
			if message.From != "Server" {
				c.d.Log.Warn("received credentials from non-Server", slog.Any("message", message))
				continue
			}
			var credentials nethernet.Credentials
			if err := json.Unmarshal([]byte(message.Data), &credentials); err != nil {
				c.d.Log.Error("error decoding credentials", internal.ErrAttr(err))
				continue
			}
			notifyCredentials := c.credentials.Load() == nil
			c.credentials.Store(&credentials)
			if notifyCredentials {
				close(c.credentialsReceived)
			}
		case MessageTypeSignal:
			signal := &nethernet.Signal{}
			if err := signal.UnmarshalText([]byte(message.Data)); err != nil {
				c.d.Log.Error("error decoding signal", internal.ErrAttr(err))
				continue
			}
			signal.NetworkID = message.From

			c.notifiersMu.Lock()
			for _, ch := range c.notifiers {
				ch <- signal
			}
			c.notifiersMu.Unlock()
		case MessageTypeError:
			// The signaling service reports an error outside of the regular nethernet.Signal flow.
			// go-nethernet does not have per-notification error callbacks anymore, so we surface this
			// as a fatal signaling error through Conn.Context().
			var err Error
			if err2 := json.Unmarshal([]byte(message.Data), &err); err2 != nil {
				c.d.Log.Error("error decoding error", internal.ErrAttr(err2))
				continue
			}
			c.cancel(&err)
			return
		case 3:
		//  unhandled message type {"Type":3,"From":"Server","Message":"{\"MessageId\":\"abc96627-33f0-4551-9e99-b90f7ab700ce\",\"AcceptedOn\":\"2025-10-26T19:58:14.9259933+00:00\"}","MessageId":"abc96627-33f0-4551-9e99-b90f7ab700ce"}
		case 4:
		//  unhandled message type {"Type":4,"From":"Server","Message":"{\"MessageId\":\"5c15c19a-f95c-4bd0-a716-bff83c1fd881\",\"ToPlayerId\":\"9853058716227158536\",\"DeliveredOn\":\"2025-10-26T19:58:19.5916651+00:00\"}","MessageId":"5c15c19a-f95c-4bd0-a716-bff83c1fd881"}
		default:
			c.d.Log.Warn("received message for unknown type", slog.Any("message", message))
		}
	}
}

// write encodes the given Message and sends it over the WebSocket connection. An error may be returned if the
// message could not be sent.
func (c *Conn) write(ctx context.Context, message Message) error {
	return wsjson.Write(ctx, c.conn, message)
}
