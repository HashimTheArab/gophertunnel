package messaging

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/creachadair/jrpc2"
	"github.com/df-mc/go-nethernet"
	"github.com/google/uuid"
)

// Conn implements a NetherNet signaling connection over JSON-RPC messaging.
type Conn struct {
	log            *slog.Logger
	conn           *websocket.Conn
	client         *jrpc2.Client
	localNetworkID uint64

	notifiers   map[int]chan<- *nethernet.Signal
	notifyCount int
	notifiersMu sync.Mutex

	credentials     *nethernet.Credentials
	credentialsTime time.Time
	credentialsMu   sync.Mutex

	expected   map[uuid.UUID]chan<- error
	expectedMu sync.Mutex

	once sync.Once

	cancel context.CancelCauseFunc
	ctx    context.Context
}

func (c *Conn) background() {
	ticker := time.NewTicker(time.Second * 15)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if err := c.ping(); err != nil {
				c.cancel(fmt.Errorf("error pinging: %w", err))
				_ = c.Close()
				return
			}
		}
	}
}

func (c *Conn) ping() error {
	ctx, cancel := context.WithTimeout(c.ctx, time.Second*5)
	defer cancel()

	resp, err := c.client.Call(ctx, "System_Ping_v1_0", map[string]any{})
	if err != nil {
		return err
	}
	if resp.Error() != nil {
		return resp.Error()
	}
	return nil
}

func (c *Conn) handleCallback(ctx context.Context, req *jrpc2.Request) (result any, err error) {
	switch req.Method() {
	case "Signaling_ReceiveMessage_v1_0":
		defer func() {
			if err != nil {
				c.log.Error(err.Error())
			}
		}()

		var batch []struct {
			From  uuid.UUID
			Inner string `json:"Message"`
			ID    string `json:"Id"`
		}
		if err := req.UnmarshalParams(&batch); err != nil {
			return nil, fmt.Errorf("handle %q: decode parameters: %w", req.Method(), err)
		}
		for _, msg := range batch {
			var inner *jrpc2.ParsedRequest
			if err := json.Unmarshal([]byte(msg.Inner), &inner); err != nil {
				return nil, fmt.Errorf("handle %q: decode inner message: %w", req.Method(), err)
			}
			if inner == nil {
				return nil, fmt.Errorf("handle %q: invalid batch message in params", req.Method())
			}

			c.log.Debug(inner.Method, "params", string(inner.Params))
			switch inner.Method {
			case "Signaling_WebRtc_v1_0":
				var params struct {
					NetherNetID string `json:"netherNetId"` // ignored, just using their messaging player ID
					Data        string `json:"message"`
				}
				if err := json.Unmarshal(inner.Params, &params); err != nil {
					return nil, fmt.Errorf("handle %q: decode parameters in inner message: %w", req.Method(), err)
				}
				if params.NetherNetID == "" || params.Data == "" {
					return nil, fmt.Errorf("handle %q: invalid inner message", req.Method())
				}

				signal := &nethernet.Signal{NetworkID: msg.From.String()}
				if err := signal.UnmarshalText([]byte(params.Data)); err != nil {
					return nil, fmt.Errorf("handle %q: decode inner message data to signal: %w", req.Method(), err)
				}

				c.notifiersMu.Lock()
				for _, ch := range c.notifiers {
					ch <- signal
				}
				c.notifiersMu.Unlock()

				b, _ := json.Marshal(map[string]any{
					"jsonrpc": "2.0",
					"method":  "Signaling_DeliveryNotification_V1_0",
					"params": map[string]any{
						"messageId": msg.ID,
					},
				})
				resp, err := c.client.Call(ctx, "Signaling_SendClientMessage_v1_0", map[string]any{
					"toPlayerId": msg.From,
					"messageId":  uuid.New(),
					"message":    string(b),
				})
				if err != nil {
					return nil, fmt.Errorf("call Signaling_SendClientMessage_v1_0: %w", err)
				}
				if resp.Error() != nil {
					return nil, resp.Error()
				}
				continue
			case "Signaling_DeliveryNotification_V1_0":
				var params struct {
					MessageID uuid.UUID `json:"messageId"`
				}
				if err := json.Unmarshal(inner.Params, &params); err != nil {
					return nil, fmt.Errorf("handle %q: decode inner parameters: %w", req.Method(), err)
				}
				c.log.Debug(params.MessageID.String())
				if params.MessageID == uuid.Nil {
					return nil, fmt.Errorf("handle %q: message ID is nil", req.Method())
				}
				c.complete(params.MessageID, nil)
				continue
			case "System_Pong_v1_0":
				continue
			default:
				return nil, fmt.Errorf("handle %q: invalid inner message method: %q", req.Method(), inner.Method)
			}
		}
		return nil, nil
	case "System_Pong_v1_0":
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown JSONRPC method: %q", req.Method())
	}
}

func (c *Conn) expect(id uuid.UUID) <-chan error {
	ch := make(chan error, 1)
	c.expectedMu.Lock()
	c.expected[id] = ch
	c.expectedMu.Unlock()
	return ch
}

func (c *Conn) release(id uuid.UUID) {
	c.expectedMu.Lock()
	ch, ok := c.expected[id]
	if ok {
		delete(c.expected, id)
	}
	c.expectedMu.Unlock()
	if ok {
		close(ch)
	}
}

func (c *Conn) complete(id uuid.UUID, err error) {
	c.expectedMu.Lock()
	ch, ok := c.expected[id]
	if ok {
		delete(c.expected, id)
	}
	c.expectedMu.Unlock()
	if ok {
		select {
		case ch <- err:
		default:
		}
		close(ch)
	}
}

// Signal sends a NetherNet signal through JSON-RPC messaging.
func (c *Conn) Signal(ctx context.Context, signal *nethernet.Signal) (err error) {
	c.log.Debug(fmt.Sprintf("Signal(%s)", signal))

	defer func() {
		if recovered := recover(); recovered != nil {
			if recoveredErr, ok := recovered.(error); ok {
				err = fmt.Errorf("recovered error: %w", recoveredErr)
				c.log.Debug(recoveredErr.Error())
				return
			}
			err = fmt.Errorf("recovered panic: %v", recovered)
			c.log.Debug(err.Error())
		}
	}()

	id := uuid.New()
	ch := c.expect(id)
	defer c.release(id)

	// jrpc2 does not expose message structs for nested payloads, so we build the body manually.
	b, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "Signaling_WebRtc_v1_0",
		"params": map[string]any{
			"netherNetId": c.localNetworkID,
			"message":     signal.String(),
		},
	})
	if err != nil {
		return fmt.Errorf("encode Signaling_WebRtc_v1_0 payload: %w", err)
	}

	messagingID, err := uuid.Parse(signal.NetworkID)
	if err != nil {
		return fmt.Errorf("invalid messaging network ID %q: %w", signal.NetworkID, err)
	}
	resp, err := c.client.Call(ctx, "Signaling_SendClientMessage_v1_0", map[string]any{
		"toPlayerId": messagingID,
		"messageId":  id,
		"message":    string(b),
	})
	if err != nil {
		return fmt.Errorf("call Signaling_SendClientMessage_v1_0: %w", err)
	}
	if resp.Error() != nil {
		return resp.Error()
	}

	if signal.Type == nethernet.SignalTypeOffer {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-c.ctx.Done():
			return context.Cause(c.ctx)
		case err := <-ch:
			return err
		}
	}
	return nil
}

// Notify registers a channel to receive incoming signals.
func (c *Conn) Notify(ch chan<- *nethernet.Signal) (stop func()) {
	c.log.Debug(fmt.Sprintf("Notify(%#v)", ch))

	c.notifiersMu.Lock()
	i := c.notifyCount
	c.notifiers[i] = ch
	c.notifyCount++
	c.notifiersMu.Unlock()

	return func() {
		c.notifiersMu.Lock()
		if _, ok := c.notifiers[i]; ok {
			delete(c.notifiers, i)
			close(ch)
		}
		c.notifiersMu.Unlock()
	}
}

// Close closes the connection and unregisters all notifiers.
func (c *Conn) Close() (err error) {
	c.once.Do(func() {
		c.notifiersMu.Lock()
		for i, ch := range c.notifiers {
			delete(c.notifiers, i)
			close(ch)
		}
		c.notifiersMu.Unlock()

		c.cancel(net.ErrClosed)
		err = c.conn.Close(websocket.StatusNormalClosure, "")
	})
	return err
}

// Context returns a context canceled on fatal signaling errors or closure.
func (c *Conn) Context() context.Context {
	return c.ctx
}

// Credentials retrieves or refreshes TURN credentials from the messaging service.
func (c *Conn) Credentials(ctx context.Context) (*nethernet.Credentials, error) {
	c.log.Debug(fmt.Sprintf("Credentials(%#v)", ctx))

	c.credentialsMu.Lock()
	defer c.credentialsMu.Unlock()

	if c.credentials != nil {
		exp := c.credentialsTime.Add(time.Second * time.Duration(c.credentials.ExpirationInSeconds))
		if time.Now().Before(exp) {
			return c.credentials, nil
		}
	}

	var credentials *nethernet.Credentials
	if err := c.client.CallResult(ctx, "Signaling_TurnAuth_v1_0", map[string]any{}, &credentials); err != nil {
		return nil, fmt.Errorf("call Signaling_TurnAuth_v1_0: %w", err)
	}
	if credentials == nil || credentials.ExpirationInSeconds == 0 {
		return nil, errors.New("call Signaling_TurnAuth_v1_0: invalid result")
	}

	c.credentials = credentials
	c.credentialsTime = time.Now()
	return c.credentials, nil
}

// NetworkID returns the local NetherNet ID used for this signaling connection.
func (c *Conn) NetworkID() string {
	return strconv.FormatUint(c.localNetworkID, 10)
}

// PongData is unused for JSON-RPC signaling.
func (c *Conn) PongData([]byte) {}

type websocketChannel struct{ *websocket.Conn }

func (ch *websocketChannel) Send(b []byte) error {
	return ch.Write(context.Background(), websocket.MessageText, b)
}

func (ch *websocketChannel) Recv() ([]byte, error) {
	_, msg, err := ch.Read(context.Background())
	return msg, err
}

func (ch *websocketChannel) Close() error {
	return ch.Conn.Close(websocket.StatusNormalClosure, "")
}
