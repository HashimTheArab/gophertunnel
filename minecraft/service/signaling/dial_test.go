package signaling

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/service"
)

func TestDialContextLogsServiceVersion(t *testing.T) {
	const serviceVersion = "2026.07.16.1"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Service-Version", serviceVersion)
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept websocket: %v", err)
			return
		}
		defer conn.CloseNow()
		_, _, _ = conn.Read(context.Background())
	}))
	defer server.Close()

	serviceURI, err := url.Parse("ws" + strings.TrimPrefix(server.URL, "http"))
	if err != nil {
		t.Fatalf("parse service URL: %v", err)
	}

	var logs bytes.Buffer
	conn, err := (Dialer{
		Environment: staticConfigurationProvider{configuration: &Configuration{
			ServiceURI:    serviceURI,
			PingFrequency: time.Hour,
		}},
		Log: slog.New(slog.NewJSONHandler(&logs, nil)),
	}).DialContext(context.Background(), staticTokenSource{token: &service.Token{
		AuthorizationHeader: "test-token",
		Claims: service.Claims{
			PlayerMessagingID: uuid.New(),
		},
	}})
	if err != nil {
		t.Fatalf("dial signaling service: %v", err)
	}
	defer conn.Close()

	var entry map[string]any
	if err := json.NewDecoder(&logs).Decode(&entry); err != nil {
		t.Fatalf("decode log entry: %v", err)
	}
	if got := entry["msg"]; got != "connected to signaling service" {
		t.Fatalf("log message = %v, want connected to signaling service", got)
	}
	if got := entry["transport"]; got != "jsonrpc" {
		t.Fatalf("transport = %v, want jsonrpc", got)
	}
	if got := entry["service_version"]; got != serviceVersion {
		t.Fatalf("service_version = %v, want %s", got, serviceVersion)
	}
}

type staticConfigurationProvider struct {
	configuration *Configuration
}

func (p staticConfigurationProvider) Configuration(context.Context, *http.Client, service.TokenSource) (*Configuration, error) {
	return p.configuration, nil
}

type staticTokenSource struct {
	token *service.Token
}

func (s staticTokenSource) ServiceToken(context.Context) (*service.Token, error) {
	return s.token, nil
}

// TURN credentials are requested as soon as the Conn connects, before any dial asks for them.
func TestDialContextRequestsCredentialsOnConnect(t *testing.T) {
	methods := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept websocket: %v", err)
			return
		}
		defer conn.CloseNow()
		_, frame, err := conn.Read(context.Background())
		if err != nil {
			return
		}
		var request struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(frame, &request)
		methods <- request.Method
		_, _, _ = conn.Read(context.Background())
	}))
	defer server.Close()

	serviceURI, err := url.Parse("ws" + strings.TrimPrefix(server.URL, "http"))
	if err != nil {
		t.Fatalf("parse service URL: %v", err)
	}
	conn, err := (Dialer{
		Environment: staticConfigurationProvider{configuration: &Configuration{
			ServiceURI:    serviceURI,
			PingFrequency: time.Hour,
		}},
		Log: slog.New(slog.DiscardHandler),
	}).DialContext(context.Background(), staticTokenSource{token: &service.Token{
		AuthorizationHeader: "test-token",
		Claims:              service.Claims{PlayerMessagingID: uuid.New()},
	}})
	if err != nil {
		t.Fatalf("dial messaging service: %v", err)
	}
	defer conn.Close()

	select {
	case got := <-methods:
		if got != MethodSignalingCredentials {
			t.Fatalf("first request = %q, want %q", got, MethodSignalingCredentials)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no TURN request after connecting")
	}
}

// Members JSON-RPC does not define are dropped, which jrpc2 would otherwise reject, and a frame that is
// not a JSON-RPC message is skipped.
func TestJSONRPCMessageIsReadLeniently(t *testing.T) {
	tests := []struct {
		frame string
		want  string // "" when the frame is skipped
	}{
		{frame: `{"jsonrpc":"2.0","id":1,"result":{}}`, want: `{"jsonrpc":"2.0","id":1,"result":{}}`},
		{frame: `{"jsonrpc":"2.0","id":1,"result":{},"traceId":"x"}`, want: `{"id":1,"jsonrpc":"2.0","result":{}}`},
		{frame: `[{"jsonrpc":"2.0","method":"m","extra":1}]`, want: `[{"jsonrpc":"2.0","method":"m"}]`},
		{frame: `not json`},
		{frame: `null`},
		{frame: `"text"`},
	}
	for _, tt := range tests {
		got, ok := jsonRPCMessage([]byte(tt.frame))
		if tt.want == "" {
			if ok {
				t.Errorf("jsonRPCMessage(%s) = %s, want it skipped", tt.frame, got)
			}
			continue
		}
		if !ok || string(got) != tt.want {
			t.Errorf("jsonRPCMessage(%s) = %s, %v, want %s", tt.frame, got, ok, tt.want)
		}
	}
}
