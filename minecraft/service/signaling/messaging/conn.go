package messaging

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/creachadair/jrpc2"
	"github.com/df-mc/go-nethernet"
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/service/signaling"
	"github.com/sandertv/gophertunnel/minecraft/service/signaling/internal"
)

// Conn implements a [nethernet.Signaling] over a JSON-RPC communication channel over WebSocket connection.
type Conn struct {
	// conn is the underlying websocket connection with signaling service.
	conn   *websocket.Conn
	client *jrpc2.Client
	// d is the Dialer used to dial this Conn.
	d Dialer
	// pmid is the Player Messaging ID extracted from JWT claims.
	pmid uuid.UUID

	// once ensures that closure of the Conn occurs only once.
	once sync.Once
	// ctx is the background context for the Conn.
	// It is canceled when an error is returned from the underlying websocket connection.
	ctx    context.Context
	cancel context.CancelCauseFunc

	notifiersMu sync.RWMutex
	notifyCount uint32
	notifiers   map[uint32]nethernet.Notifier

	pending *internal.PendingMap

	// credentials is the last known credentials received from the server.
	// This is cached until it expires to prevent excessive call.
	credentials *nethernet.Credentials
	// credentialsExpiry is the expiry of the credentials, estimated from [nethernet.Credentials.ExpirationInSeconds].
	credentialsExpiry time.Time
	// credentialsRequest is the TURN request in flight, if any.
	credentialsRequest *credentialsRequest
	// credentialsRefresh requests new credentials once credentialsExpiry passes.
	credentialsRefresh *time.Timer
	// credentialsMu guards credentials, credentialsExpiry, credentialsRequest and credentialsRefresh.
	credentialsMu sync.Mutex
}

// Signal sends a [nethernet.Signal] to a network. In the JSON-RPC signaling path,
// signal.NetworkID is the remote player's messaging UUID rather than a NetherNet ID.
func (conn *Conn) Signal(ctx context.Context, signal *nethernet.Signal) error {
	messagingID, err := uuid.Parse(signal.NetworkID)
	if err != nil {
		return fmt.Errorf("signaling/messaging: recipient ID must be a UUID: %q", signal.NetworkID)
	}

	id := uuid.New()
	msg := map[string]any{
		"params": map[string]any{
			"netherNetId": conn.d.NetworkID,
			"message":     signal.String(),
		},
		"jsonrpc": "2.0",
		"method":  MethodSignalingWebRTC,
	}

	if signal.Type != nethernet.SignalTypeOffer || conn.d.IgnoreDeliveryNotification {
		return conn.send(ctx, id, msg, messagingID)
	}

	ch := conn.pending.Add(id)
	defer conn.pending.Remove(id)

	if err := conn.send(ctx, id, msg, messagingID); err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-conn.ctx.Done():
		return context.Cause(conn.ctx)
	case err := <-ch:
		return err
	}
}

// send submits the JSON-RPC message encapsulated in an envelope that contains the recipient ID.
func (conn *Conn) send(ctx context.Context, id uuid.UUID, inner any, messagingID uuid.UUID) error {
	data, err := json.Marshal(inner)
	if err != nil {
		return fmt.Errorf("encode inner message: %w", err)
	}
	_, err = conn.client.Call(ctx, MethodSignalingSendMessage, map[string]any{
		"toPlayerId": messagingID,
		"messageId":  id,
		"message":    string(data),
	})
	if err != nil {
		return fmt.Errorf("call %q: %w", MethodSignalingSendMessage, err)
	}
	return nil
}

// Notify registers n to receive incoming NetherNet signals.
func (conn *Conn) Notify(n nethernet.Notifier) func() {
	if n == nil {
		panic("signaling/messaging: nil Notifier")
	}
	conn.notifiersMu.Lock()
	id := conn.notifyCount
	conn.notifyCount++
	conn.notifiers[id] = n
	conn.notifiersMu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			conn.notifiersMu.Lock()
			delete(conn.notifiers, id)
			conn.notifiersMu.Unlock()
		})
	}
}

// Credentials returns the TURN credentials last received from the server, waiting for the request
// in flight if they are missing or expired. A failed, unanswered or undecodable request yields no
// ICE servers, so connections still gather host candidates; only closure of the Conn or ctx
// returns an error. Concurrent callers share one request, and each stops waiting when its ctx is done.
func (conn *Conn) Credentials(ctx context.Context) (*nethernet.Credentials, error) {
	select {
	case <-conn.ctx.Done():
		return nil, context.Cause(conn.ctx)
	default:
	}

	conn.credentialsMu.Lock()
	if conn.credentials != nil && time.Now().Before(conn.credentialsExpiry) {
		credentials := conn.credentials
		conn.credentialsMu.Unlock()
		return credentials, nil
	}
	request := conn.startCredentialsRequestLocked()
	conn.credentialsMu.Unlock()

	select {
	case <-request.done:
		return request.credentials, request.err
	case <-ctx.Done():
		return nil, &CredentialsError{Method: MethodSignalingCredentials, Err: context.Cause(ctx)}
	case <-conn.ctx.Done():
		return nil, context.Cause(conn.ctx)
	}
}

// credentialsRequest is one TURN request whose result every waiting Credentials call shares.
type credentialsRequest struct {
	done        chan struct{} // closed once credentials and err are set
	credentials *nethernet.Credentials
	err         error
}

// credentialsRequestTimeout is how long the Bedrock client waits for a JSON-RPC response before
// failing the request.
const credentialsRequestTimeout = 60 * time.Second

// refreshCredentials starts a TURN request unless one is in flight. The Conn calls it once
// connected and again when the received credentials expire.
func (conn *Conn) refreshCredentials() {
	conn.credentialsMu.Lock()
	if conn.ctx.Err() == nil {
		conn.startCredentialsRequestLocked()
	}
	conn.credentialsMu.Unlock()
}

// startCredentialsRequestLocked returns the TURN request in flight, starting one if there is none.
// credentialsMu must be held.
func (conn *Conn) startCredentialsRequestLocked() *credentialsRequest {
	if conn.credentialsRequest == nil {
		conn.credentialsRequest = &credentialsRequest{done: make(chan struct{})}
		go conn.requestCredentials(conn.credentialsRequest)
	}
	return conn.credentialsRequest
}

// requestCredentials performs request. An answer is cached until now plus its ExpirationInSeconds,
// when a refresh is scheduled; a failure leaves the cache and its expiry as they were.
func (conn *Conn) requestCredentials(request *credentialsRequest) {
	ctx, cancel := context.WithTimeout(conn.ctx, credentialsRequestTimeout)
	defer cancel()
	var credentials *nethernet.Credentials
	err := conn.client.CallResult(ctx, MethodSignalingCredentials, map[string]any{}, &credentials)
	if err == nil && credentials == nil {
		err = errors.New("null result")
	}
	now := time.Now()

	conn.credentialsMu.Lock()
	switch {
	case err != nil && conn.ctx.Err() != nil:
		request.err = &CredentialsError{Method: MethodSignalingCredentials, Err: err}
	case err != nil:
		conn.d.Log.Warn("TURN credentials unavailable, gathering without relay servers",
			slog.Any("error", &CredentialsError{Method: MethodSignalingCredentials, Err: err}))
		request.credentials = &nethernet.Credentials{}
	default:
		request.credentials = credentials
		conn.credentials = credentials
		conn.credentialsExpiry = now.Add(time.Duration(credentials.ExpirationInSeconds) * time.Second)
		if conn.credentialsRefresh != nil {
			conn.credentialsRefresh.Stop()
			conn.credentialsRefresh = nil
		}
		// A non-positive expiry is already due, so the next Credentials call requests again.
		if wait := conn.credentialsExpiry.Sub(now); wait > 0 && conn.ctx.Err() == nil {
			conn.credentialsRefresh = time.AfterFunc(wait, conn.refreshCredentials)
		}
	}
	conn.credentialsRequest = nil
	conn.credentialsMu.Unlock()
	close(request.done)
}

// PongData ...
func (conn *Conn) PongData(b []byte) {
}

// NetworkID returns the local NetherNet network ID of the Conn. It may be specified from [Dialer.NetworkID],
// otherwise a random value will be automatically set from [rand.Uint64] in set up during [Dialer.DialContext].
// It is utilized by [nethernet.Listener] and [nethernet.Dialer] to obtain its local network ID to listen.
func (conn *Conn) NetworkID() string {
	return conn.d.NetworkID
}

// PlayerMessagingID returns the player messaging ID of the current authenticated user.
func (conn *Conn) PlayerMessagingID() uuid.UUID {
	return conn.pmid
}

// Close closes the Conn. It ensures that the Conn is closed only once.
func (conn *Conn) Close() (err error) {
	return conn.close(net.ErrClosed)
}

// Context returns the background context of the [Conn].
// It is canceled if the underlying WebSocket connection was closed.
func (conn *Conn) Context() context.Context {
	return conn.ctx
}

// close cancels the background context of the Conn and closes the underlying WebSocket connection.
func (conn *Conn) close(cause error) (err error) {
	conn.once.Do(func() {
		conn.stop(cause)
		err = conn.client.Close()
	})
	return err
}

// stop cancels the Conn context and unregisters signal notifiers without
// closing the JSON-RPC client. It is used when the client stops itself.
func (conn *Conn) stop(cause error) {
	conn.d.Log.Debug("closing connection", slog.Any("cause", cause))
	conn.cancel(cause)
	conn.credentialsMu.Lock()
	if conn.credentialsRefresh != nil {
		conn.credentialsRefresh.Stop()
		conn.credentialsRefresh = nil
	}
	conn.credentialsMu.Unlock()
}

// handleCallback handles an JSON-RPC request method called by the server.
// It is used as the [jrpc2.ClientOptions.OnCallback] handler in the client.
func (conn *Conn) handleCallback(ctx context.Context, request *jrpc2.Request) (any, error) {
	switch request.Method() {
	case MethodSystemPong:
		return nil, nil
	case MethodSignalingReceiveMessage:
		return conn.handleMessage(ctx, request)
	case MethodSignalingReceiveError:
		return nil, conn.handleReceiveError([]byte(request.ParamString()))
	default:
		return nil, fmt.Errorf("received message for unknown method: %q", request.Method())
	}
}

// handleMessage handles one or more messages received from the server.
// It decodes each message included in the request and calls handleInnerMessage.
func (conn *Conn) handleMessage(ctx context.Context, request *jrpc2.Request) (v any, err error) {
	var params envelopeParams
	if err := request.UnmarshalParams(&params); err != nil {
		return nil, fmt.Errorf("decode parameters: %w", err)
	}
	for _, e := range params {
		if e == nil {
			err = errors.Join(err, errors.New("signaling/messaging: nil envelope"))
			continue
		}
		if err2 := conn.handleInnerMessage(ctx, e); err2 != nil {
			err = errors.Join(err, err2)
		}
	}
	return nil, err
}

// handleReceiveError fails the pending signal a delivery error names. An error that names no
// pending signal, or that cannot be read, is logged and otherwise ignored.
func (conn *Conn) handleReceiveError(params []byte) error {
	var e struct {
		MessageID uuid.UUID `json:"messageId"`
		Code      int       `json:"code"`
		Message   string    `json:"message"`
	}
	if err := json.Unmarshal(params, &e); err != nil || e.MessageID == uuid.Nil {
		conn.d.Log.Debug("received delivery error without a message", slog.Int("code", e.Code))
		return nil
	}
	if !conn.pending.Done(e.MessageID, &signaling.Error{Code: e.Code, Message: e.Message}) {
		conn.d.Log.Debug("received delivery error for unknown message", slog.String("message_id", e.MessageID.String()))
	}
	return nil
}

// envelopeParams accepts both the single-message object and legacy batched array
// forms used by the Player Messaging service.
type envelopeParams []*envelope

func (p *envelopeParams) UnmarshalJSON(data []byte) error {
	var batch []*envelope
	if err := json.Unmarshal(data, &batch); err == nil {
		*p = batch
		return nil
	}

	var single *envelope
	if err := json.Unmarshal(data, &single); err != nil {
		return err
	}
	*p = []*envelope{single}
	return nil
}

// envelope wraps a JSON-RPC message delivered through Player Messaging.
type envelope struct {
	// From identifies the Player Messaging ID of the sender.
	From uuid.UUID
	// Message is the inner JSON-RPC request sent by the remote network.
	Message *jrpc2.ParsedRequest
	// RawMessage contains the raw data of the message.
	RawMessage string `json:"-"`
	// ID is the unique message ID associated to this message.
	// It is used to track the delivery status of a message.
	ID uuid.UUID `json:"Id"`
}

// UnmarshalJSON decodes an envelope whose Message field is encoded on the
// wire as a JSON string containing a nested JSON-RPC request.
func (m *envelope) UnmarshalJSON(b []byte) error {
	type Alias envelope
	data := struct {
		*Alias
		Message string
	}{Alias: (*Alias)(m)}
	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(data.Message), &m.Message); err != nil {
		return fmt.Errorf("decode message: %w", err)
	}
	if m.Message == nil {
		return errors.New("decode message: nil request")
	}
	m.RawMessage = data.Message
	return nil
}

// handleInnerMessage handles an inner message encapsulated in the given envelope.
func (conn *Conn) handleInnerMessage(ctx context.Context, envelope *envelope) error {
	switch envelope.Message.Method {
	case MethodSignalingDeliveryNotification:
		if conn.d.IgnoreDeliveryNotification {
			return nil
		}
		var params struct {
			MessageID uuid.UUID `json:"messageId"`
		}
		if err := json.Unmarshal(envelope.Message.Params, &params); err != nil {
			return fmt.Errorf("decode request parameters: %w", err)
		}
		if params.MessageID == uuid.Nil {
			return errors.New("invalid request parameters")
		}
		if !conn.pending.Done(params.MessageID, nil) {
			conn.d.Log.Debug("received delivery notification for unknown message", slog.String("message_id", params.MessageID.String()))
		}
		return nil
	case MethodSignalingWebRTC:
		var params struct {
			NetherNetID string `json:"netherNetId"`
			Message     string `json:"message"`
		}
		if err := json.Unmarshal(envelope.Message.Params, &params); err != nil {
			return fmt.Errorf("decode request parameters: %w", err)
		}
		signal := &nethernet.Signal{NetworkID: envelope.From.String()}
		// Dropped without acknowledgement; an error here would log the raw payload.
		if err := signal.UnmarshalText([]byte(params.Message)); err != nil {
			conn.d.Log.Debug("incoming signal was not accepted",
				slog.Uint64("connection_id", signal.ConnectionID), slog.String("reason", "undecodable"))
			return nil
		}

		if !conn.notifySignal(signal) {
			conn.d.Log.Debug("incoming signal was not accepted",
				slog.Uint64("connection_id", signal.ConnectionID))
			return nil
		}

		if err := conn.send(ctx, uuid.New(), map[string]any{
			"params": map[string]any{
				"messageId": envelope.ID,
			},
			"jsonrpc": "2.0",
			"method":  MethodSignalingDeliveryNotification,
		}, envelope.From); err != nil {
			return fmt.Errorf("acknowledge message: %w", err)
		}
		return nil
	default:
		if envelope.RawMessage != "" {
			dec := json.NewDecoder(strings.NewReader(envelope.RawMessage))
			dec.DisallowUnknownFields()
			var e signaling.Error
			if err := dec.Decode(&e); err == nil {
				if !conn.pending.Done(envelope.ID, &e) {
					conn.d.Log.Debug("received error for unknown message", slog.String("message_id", envelope.ID.String()))
				}
				return nil
			}
		}
		return fmt.Errorf("unknown inner request method: %q", envelope.Message.Method)
	}
}

// notifySignal sends a signal to a stable snapshot of the registered
// notifiers and reports whether at least one accepted it.
func (conn *Conn) notifySignal(signal *nethernet.Signal) bool {
	conn.notifiersMu.RLock()
	notifiers := maps.Clone(conn.notifiers)
	conn.notifiersMu.RUnlock()
	return internal.NotifySignal(notifiers, signal)
}

// ping sends [MethodSystemPing] as a notification at the given interval. Like the Bedrock client,
// it never closes the Conn: a missing reply goes unnoticed and a failed send is only logged, since
// a broken connection is detected by its reader.
func (conn *Conn) ping(frequency time.Duration) {
	if frequency <= 0 {
		frequency = signaling.DefaultPingFrequency
	}
	ticker := time.NewTicker(frequency)
	defer ticker.Stop()

	for {
		select {
		case <-conn.ctx.Done():
			return
		case <-ticker.C:
			if err := conn.client.Notify(conn.ctx, MethodSystemPing, map[string]any{}); err != nil {
				conn.d.Log.Error("error pinging", slog.Any("error", err))
			}
		}
	}
}

const (
	// MethodSystemPing is the JSON-RPC method name used by the client to
	// ping the server and keep the connection alive.
	MethodSystemPing = "System_Ping_v1_0"
	// MethodSystemPong is called by the server in response to [MethodSystemPing] to ping the client.
	// The client must respond with a nil value in order to complete the request.
	MethodSystemPong = "System_Pong_v1_0"

	// MethodSignalingCredentials is the JSON-RPC method name used by the
	// client to request [nethernet.Credentials] for Microsoft's STUN/TURN
	// servers.
	MethodSignalingCredentials = "Signaling_TurnAuth_v1_0"
	// MethodSignalingReceiveMessage is the JSON-RPC method name used by
	// the server to deliver one or more envelopes received from remote peers.
	MethodSignalingReceiveMessage = "Signaling_ReceiveMessage_v1_0"
	// MethodSignalingReceiveError is the JSON-RPC method name used by the server to report that
	// a message the client sent could not be delivered.
	MethodSignalingReceiveError = "Signaling_ReceiveError_v1_0"
	// MethodSignalingSendMessage is the JSON-RPC method name used by the
	// client to send an inner signaling message to a remote peer.
	MethodSignalingSendMessage = "Signaling_SendClientMessage_v1_0"

	// MethodSignalingDeliveryNotification is the JSON-RPC method name used
	// by an inner message to acknowledge receipt of an earlier message identified
	// by its outer envelope ID. Note the capitalized 'V' on the version.
	MethodSignalingDeliveryNotification = "Signaling_DeliveryNotification_V1_0"
	// MethodSignalingWebRTC is the JSON-RPC method name used by an inner
	// message that carries a [nethernet.Signal] used for WebRTC negotiation.
	MethodSignalingWebRTC = "Signaling_WebRtc_v1_0"
)
