package messaging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"github.com/creachadair/jrpc2/handler"
	"github.com/df-mc/go-nethernet"
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/service/signaling"
	"github.com/sandertv/gophertunnel/minecraft/service/signaling/internal"
)

func TestCredentialsRejectsWarmCacheAfterClose(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(net.ErrClosed)
	conn := &Conn{
		ctx:               ctx,
		credentials:       &nethernet.Credentials{ExpirationInSeconds: 60},
		credentialsExpiry: time.Now().Add(time.Minute),
	}
	if _, err := conn.Credentials(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Credentials() error = %v, want net.ErrClosed", err)
	}
}

// credentialsConn returns a Conn whose TURN requests are answered by handle, and the request count.
func credentialsConn(t *testing.T, handle func() (json.RawMessage, error)) (*Conn, *atomic.Int32) {
	t.Helper()
	calls := new(atomic.Int32)
	clientChannel, serverChannel := channel.Direct()
	server := jrpc2.NewServer(handler.Map{
		MethodSignalingCredentials: handler.New(func(context.Context, map[string]any) (json.RawMessage, error) {
			calls.Add(1)
			return handle()
		}),
	}, nil).Start(serverChannel)
	t.Cleanup(server.Stop)
	client := jrpc2.NewClient(clientChannel, nil)
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithCancelCause(context.Background())
	conn := &Conn{client: client, ctx: ctx, cancel: cancel, d: Dialer{Log: slog.New(slog.DiscardHandler)}}
	t.Cleanup(func() { conn.stop(net.ErrClosed) })
	return conn, calls
}

// turnAnswer is a TURN answer with one server that expires after the given seconds.
func turnAnswer(seconds int) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"ExpirationInSeconds":%d,"TurnAuthServers":[{"Username":"u","Password":"p","Urls":["turn:a"]}]}`, seconds))
}

// A failed or undecodable TURN answer yields no ICE servers instead of failing the dial.
func TestCredentialsFailureYieldsNoServers(t *testing.T) {
	for name, handle := range map[string]func() (json.RawMessage, error){
		"call error":    func() (json.RawMessage, error) { return nil, errors.New("turn unavailable") },
		"null result":   func() (json.RawMessage, error) { return json.RawMessage(`null`), nil },
		"wrong shape":   func() (json.RawMessage, error) { return json.RawMessage(`{"ExpirationInSeconds":"soon"}`), nil },
		"not an object": func() (json.RawMessage, error) { return json.RawMessage(`[]`), nil },
	} {
		t.Run(name, func(t *testing.T) {
			conn, _ := credentialsConn(t, handle)
			credentials, err := conn.Credentials(context.Background())
			if err != nil {
				t.Fatalf("Credentials() error = %v, want nil", err)
			}
			if len(credentials.ICEServers) != 0 {
				t.Fatalf("Credentials() servers = %v, want none", credentials.ICEServers)
			}
		})
	}
}

// Any expiry is accepted; a non-positive one is already due, so the next call requests again.
func TestCredentialsAcceptNonPositiveExpiry(t *testing.T) {
	for _, seconds := range []int{0, -1} {
		t.Run(fmt.Sprint(seconds), func(t *testing.T) {
			conn, calls := credentialsConn(t, func() (json.RawMessage, error) { return turnAnswer(seconds), nil })
			for range 2 {
				credentials, err := conn.Credentials(context.Background())
				if err != nil || len(credentials.ICEServers) != 1 {
					t.Fatalf("Credentials() = %v, %v, want one server", credentials, err)
				}
			}
			if got := calls.Load(); got != 2 {
				t.Fatalf("TURN requests = %d, want 2", got)
			}
		})
	}
}

// A caller whose ctx ends stops waiting without cancelling the request another caller shares.
func TestCredentialsWaitHonoursCallerContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		conn, calls := credentialsConn(t, func() (json.RawMessage, error) {
			<-release
			return turnAnswer(60), nil
		})
		conn.refreshCredentials()
		shared := make(chan *nethernet.Credentials)
		go func() {
			credentials, _ := conn.Credentials(context.Background())
			shared <- credentials
		}()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := conn.Credentials(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Credentials() error = %v, want context deadline exceeded", err)
		}
		close(release)
		if credentials := <-shared; credentials == nil || len(credentials.ICEServers) != 1 {
			t.Fatalf("shared Credentials() = %v, want one server", credentials)
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("TURN requests = %d, want 1", got)
		}
	})
}

// An unanswered TURN request fails after the client's 60 second JSON-RPC timeout, yielding no
// relay servers, and the next call requests again.
func TestCredentialsUnansweredRequestFallsBack(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		defer close(release)
		conn, calls := credentialsConn(t, func() (json.RawMessage, error) {
			<-release
			return nil, errors.New("released")
		})
		for want := int32(1); want <= 2; want++ {
			start := time.Now()
			credentials, err := conn.Credentials(context.Background())
			if err != nil || len(credentials.ICEServers) != 0 {
				t.Fatalf("Credentials() = %v, %v, want no servers and no error", credentials, err)
			}
			if waited := time.Since(start); waited != 60*time.Second {
				t.Fatalf("unanswered request failed after %v, want 60s", waited)
			}
			synctest.Wait()
			if got := calls.Load(); got != want {
				t.Fatalf("TURN requests = %d, want %d", got, want)
			}
		}
	})
}

// Received credentials are requested again in the background as soon as they expire, not before.
func TestCredentialsRefreshOnExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn, calls := credentialsConn(t, func() (json.RawMessage, error) { return turnAnswer(60), nil })
		conn.refreshCredentials()
		synctest.Wait()
		time.Sleep(60*time.Second - time.Nanosecond)
		synctest.Wait()
		if got := calls.Load(); got != 1 {
			t.Fatalf("TURN requests before expiry = %d, want 1", got)
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if got := calls.Load(); got != 2 {
			t.Fatalf("TURN requests after expiry = %d, want 2", got)
		}
		conn.stop(net.ErrClosed)
	})
}

// No TURN request is made after the Conn closes, even when a refresh was due.
func TestCredentialsRefreshStopsOnClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn, calls := credentialsConn(t, func() (json.RawMessage, error) { return turnAnswer(60), nil })
		conn.refreshCredentials()
		synctest.Wait()
		conn.stop(net.ErrClosed)
		time.Sleep(time.Hour)
		synctest.Wait()
		if got := calls.Load(); got != 1 {
			t.Fatalf("TURN requests after close = %d, want 1", got)
		}
	})
}

// Pings are notifications: they carry no id and an unanswered ping keeps the Conn open.
func TestPingIsANotification(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		clientChannel, serverChannel := channel.Direct()
		client := jrpc2.NewClient(clientChannel, nil)
		defer client.Close()
		defer serverChannel.Close()
		ctx, cancel := context.WithCancelCause(context.Background())
		defer cancel(net.ErrClosed)
		conn := &Conn{client: client, ctx: ctx, cancel: cancel, d: Dialer{Log: slog.New(slog.DiscardHandler)}}
		go conn.ping(time.Second)

		for range 2 {
			frame, err := serverChannel.Recv()
			if err != nil {
				t.Fatalf("receive ping: %v", err)
			}
			var ping map[string]json.RawMessage
			if err := json.Unmarshal(frame, &ping); err != nil {
				t.Fatalf("decode ping %s: %v", frame, err)
			}
			if _, ok := ping["id"]; ok || string(ping["method"]) != `"`+MethodSystemPing+`"` {
				t.Fatalf("ping frame = %s, want a %s notification", frame, MethodSystemPing)
			}
		}
		if err := ctx.Err(); err != nil {
			t.Fatalf("Conn closed after unanswered pings: %v", context.Cause(ctx))
		}
		cancel(net.ErrClosed)
	})
}

// A ping that cannot be sent is logged without closing the Conn.
func TestPingSendFailureKeepsConn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		clientChannel, serverChannel := channel.Direct()
		client := jrpc2.NewClient(clientChannel, nil)
		defer client.Close()
		_ = serverChannel.Close()
		ctx, cancel := context.WithCancelCause(context.Background())
		defer cancel(net.ErrClosed)
		conn := &Conn{client: client, ctx: ctx, cancel: cancel, d: Dialer{Log: slog.New(slog.DiscardHandler)}}
		go conn.ping(time.Second)

		time.Sleep(3 * time.Second)
		synctest.Wait()
		if err := ctx.Err(); err != nil {
			t.Fatalf("Conn closed after a failed ping: %v", context.Cause(ctx))
		}
		cancel(net.ErrClosed)
	})
}

// acceptingNotifier accepts every signal delivered by a test.
type acceptingNotifier struct{}

// NotifySignal accepts the signal.
func (acceptingNotifier) NotifySignal(*nethernet.Signal) bool { return true }

// Rejected or undecodable signals are dropped unacknowledged, without an error that would log
// the raw payload.
func TestConnHandleInnerMessageDoesNotAcknowledgeRejectedSignal(t *testing.T) {
	for _, typ := range []string{nethernet.SignalTypeOffer, "remote-controlled-type"} {
		t.Run(typ, func(t *testing.T) {
			signal := &nethernet.Signal{
				Type:         typ,
				ConnectionID: 42,
				Data:         "sensitive-payload",
			}
			params, err := json.Marshal(map[string]any{
				"netherNetId": "network",
				"message":     signal.String(),
			})
			if err != nil {
				t.Fatalf("marshal params: %v", err)
			}
			var logs bytes.Buffer
			conn := &Conn{
				d: Dialer{Log: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{
					Level: slog.LevelDebug,
				}))},
				notifiers: make(map[uint32]nethernet.Notifier),
			}
			err = conn.handleInnerMessage(context.Background(), &envelope{
				From: uuid.New(),
				ID:   uuid.New(),
				Message: &jrpc2.ParsedRequest{
					Method: MethodSignalingWebRTC,
					Params: params,
				},
			})
			if err != nil {
				t.Fatalf("handleInnerMessage() error = %v, want nil", err)
			}
			if strings.Contains(logs.String(), signal.Data) {
				t.Fatal("rejected signal log contains the signal payload")
			}
			if strings.Contains(logs.String(), signal.Type) {
				t.Fatal("rejected signal log contains the remote-controlled signal type")
			}
			var entry map[string]any
			if err := json.NewDecoder(&logs).Decode(&entry); err != nil {
				t.Fatalf("decode log entry: %v", err)
			}
			if got := entry["msg"]; got != "incoming signal was not accepted" {
				t.Fatalf("log message = %v, want incoming signal was not accepted", got)
			}
		})
	}
}

func TestConnHandleInnerMessageAcknowledgesAcceptedSignal(t *testing.T) {
	type sendMessageParams struct {
		ToPlayerID uuid.UUID `json:"toPlayerId"`
		MessageID  uuid.UUID `json:"messageId"`
		Message    string    `json:"message"`
	}
	received := make(chan sendMessageParams, 1)
	clientChannel, serverChannel := channel.Direct()
	server := jrpc2.NewServer(handler.Map{
		MethodSignalingSendMessage: handler.New(func(_ context.Context, params *sendMessageParams) error {
			received <- *params
			return nil
		}),
	}, nil).Start(serverChannel)
	defer server.Stop()
	client := jrpc2.NewClient(clientChannel, nil)
	defer client.Close()

	signal := &nethernet.Signal{
		Type:         nethernet.SignalTypeOffer,
		ConnectionID: 42,
		Data:         "offer",
	}
	params, err := json.Marshal(map[string]any{
		"netherNetId": "network",
		"message":     signal.String(),
	})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	messageID, senderID := uuid.New(), uuid.New()
	conn := &Conn{
		client:    client,
		d:         Dialer{Log: slog.Default()},
		notifiers: map[uint32]nethernet.Notifier{0: acceptingNotifier{}},
	}
	if err := conn.handleInnerMessage(context.Background(), &envelope{
		From: senderID,
		ID:   messageID,
		Message: &jrpc2.ParsedRequest{
			Method: MethodSignalingWebRTC,
			Params: params,
		},
	}); err != nil {
		t.Fatalf("handleInnerMessage() error = %v", err)
	}

	request := <-received
	if request.ToPlayerID != senderID {
		t.Fatalf("delivery recipient = %s, want %s", request.ToPlayerID, senderID)
	}
	var delivery struct {
		Method string `json:"method"`
		Params struct {
			MessageID uuid.UUID `json:"messageId"`
		} `json:"params"`
	}
	if err := json.Unmarshal([]byte(request.Message), &delivery); err != nil {
		t.Fatalf("decode delivery notification: %v", err)
	}
	if delivery.Method != MethodSignalingDeliveryNotification {
		t.Fatalf("delivery method = %q, want %q", delivery.Method, MethodSignalingDeliveryNotification)
	}
	if delivery.Params.MessageID != messageID {
		t.Fatalf("delivery message ID = %s, want %s", delivery.Params.MessageID, messageID)
	}
}

// A delivery error from the service fails the signal it names instead of being refused as an
// unknown method; an error naming no pending signal is ignored.
func TestReceiveErrorFailsThePendingSignal(t *testing.T) {
	conn := &Conn{d: Dialer{Log: slog.New(slog.DiscardHandler)}, pending: internal.NewPendingMap()}
	id := uuid.New()
	ch := conn.pending.Add(id)
	params := []byte(`{"messageId":"` + id.String() + `","code":404,"message":"recipient offline"}`)
	if err := conn.handleReceiveError(params); err != nil {
		t.Fatalf("handleReceiveError() error = %v", err)
	}
	select {
	case err := <-ch:
		var serviceErr *signaling.Error
		if !errors.As(err, &serviceErr) || serviceErr.Code != 404 || serviceErr.Message != "recipient offline" {
			t.Fatalf("pending signal failed with %v", err)
		}
	default:
		t.Fatal("pending signal was not failed")
	}
	if err := conn.handleReceiveError([]byte(`{"code":1}`)); err != nil {
		t.Fatalf("an error naming no signal: %v", err)
	}
}
