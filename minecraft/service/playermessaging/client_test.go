package playermessaging

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/service"
)

type fixedTokens struct{}

func (fixedTokens) ServiceToken(context.Context) (*service.Token, error) {
	return &service.Token{AuthorizationHeader: "MCToken synthetic", ValidUntil: time.Now().Add(time.Hour)}, nil
}

// Authored from the 26.30 client's PlayerMessagingServiceSession and MessageData parsers, not a capture.
const refreshFixture = `{"result":{"continuationToken":"c-2","messages":[{"id":"m1","instanceId":"i1","reportId":"r1",
"surface":"PlayButton","template":"ImageThenText","messageText":{"header":"Hi","body":"Text"},
"buttons":{"primary":{"text":"Go","link":"minecraft://x","action":"Internal"}},
"images":{"hero":{"url":"https://cdn.example.test/h.png","imageSize":{"width":64,"height":32}}}}],
"inboxSummary":{"totalNumberOfMessages":3,"categories":[{"totalNumberOfMessages":3,"totalNumberOfUnreadMessages":1,
"categoryInfo":{"type":"News","name":"News"},"messages":[]}]},"inboxSettings":{"showMessageBadges":true}}}`

func newClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	env := new(Environment)
	if err := json.Unmarshal([]byte(`{"serviceUri":"`+server.URL+`"}`), env); err != nil {
		t.Fatal(err)
	}
	env.HTTPClient = server.Client()
	return env.New(fixedTokens{})
}

// A refresh decodes typed messages and carries the continuation token into the next call.
func TestRefreshCarriesTheContinuation(t *testing.T) {
	var bodies []map[string]string
	client := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		bodies = append(bodies, body)
		_, _ = w.Write([]byte(refreshFixture))
	})
	session, err := client.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	message := session.Messages[0]
	if message.Buttons["primary"].Action != "Internal" || message.Images["hero"].Size.Width != 64 || message.Text.Header != "Hi" {
		t.Fatalf("message = %+v", message)
	}
	if category := session.InboxSummary.Categories[0]; category.Unread != 1 || category.Info.Type != "News" {
		t.Fatalf("category = %+v", category)
	}
	if _, err := client.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if bodies[0]["continuationToken"] != "" || bodies[1]["continuationToken"] != "c-2" || bodies[1]["sessionId"] != client.SessionID() {
		t.Fatalf("bodies = %v", bodies)
	}
}

// Concurrent refreshes must carry each preceding response's continuation token.
func TestConcurrentRefreshCarriesTheContinuation(t *testing.T) {
	var mu sync.Mutex
	var requests int
	var continuation string
	client := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if body["continuationToken"] != continuation {
			t.Errorf("continuation = %q, want %q", body["continuationToken"], continuation)
		}
		requests++
		continuation = strconv.Itoa(requests)
		_ = json.NewEncoder(w).Encode(map[string]any{"result": Session{ContinuationToken: continuation}})
	})
	var callers sync.WaitGroup
	start := make(chan struct{})
	for range 8 {
		callers.Go(func() {
			<-start
			if _, err := client.Refresh(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	close(start)
	callers.Wait()
	if got := client.current(); got != "8" {
		t.Fatalf("final continuation = %q, want 8", got)
	}
}

// Events name the session with the refresh's continuation, and a malformed refresh is an error.
func TestReportEventsAndMalformedRefresh(t *testing.T) {
	var body struct {
		SessionID string `json:"SessionId"`
		Events    []map[string]string
	}
	client := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1.0/messages/event" {
			_ = json.NewDecoder(r.Body).Decode(&body)
			return
		}
		_, _ = w.Write([]byte(`{"result":{"messages":{"not":"an array"}}}`))
	})
	if _, err := client.Refresh(context.Background()); err == nil {
		t.Fatal("a malformed refresh decoded")
	}
	if err := client.ReportEvents(context.Background(), Event{Type: EventClick, InstanceID: "i1", ReportID: "r1", ButtonID: "primary"}); err != nil {
		t.Fatal(err)
	}
	if body.SessionID != client.SessionID() || body.Events[0]["eventType"] != "Click" || body.Events[0]["buttonId"] != "primary" {
		t.Fatalf("event body = %+v", body)
	}
}
