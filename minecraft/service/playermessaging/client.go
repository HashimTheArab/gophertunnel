// Package playermessaging reads the player messaging service that feeds the start screen's
// message tiles, inbox, toasts and announcements.
package playermessaging

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/service"
	"github.com/sandertv/gophertunnel/minecraft/service/internal"
	"github.com/sandertv/gophertunnel/minecraft/service/internal/request"
)

// Environment is the discovered player messaging endpoint.
type Environment struct {
	internal.ServiceEnvironment
	// HTTPClient sends the requests; nil uses http.DefaultClient.
	HTTPClient *http.Client `json:"-"`
	// Language is the player's locale sent as Accept-Language, such as "en-US"; empty sends none.
	Language string `json:"-"`
}

// ServiceName implements [service.Environment] and returns "messaging".
func (*Environment) ServiceName() string { return "messaging" }

// New returns a Client with a fresh messaging session, authorized by src.
func (e *Environment) New(src service.TokenSource) *Client {
	return &Client{env: e, src: src, sessionID: uuid.NewString()}
}

// Client holds one messaging session; the service's continuation token is carried across calls.
// It is safe for concurrent use.
type Client struct {
	env       *Environment
	src       service.TokenSource
	sessionID string

	mu           sync.Mutex
	continuation string
}

// SessionID is the session every request of this client names.
func (c *Client) SessionID() string { return c.sessionID }

// options returns the headers the game sends with every messaging request.
func (c *Client) options() request.Options {
	header := http.Header{"Session-Id": {c.sessionID}}
	if c.env.Language != "" {
		header.Set("Accept-Language", c.env.Language)
	}
	return request.Options{Header: header}
}

// current returns the continuation token from the last completed refresh.
func (c *Client) current() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.continuation
}

// Session is the answer of a session refresh.
type Session struct {
	ContinuationToken string          `json:"continuationToken"`
	Messages          []Message       `json:"messages"`
	InboxSummary      InboxSummary    `json:"inboxSummary"`
	InboxSettings     json.RawMessage `json:"inboxSettings"`
}

// InboxSummary counts the inbox and lists it per category.
type InboxSummary struct {
	Total      int        `json:"totalNumberOfMessages"`
	Categories []Category `json:"categories"`
}

// Category is one inbox category with its messages.
type Category struct {
	Total             int          `json:"totalNumberOfMessages"`
	Unread            int          `json:"totalNumberOfUnreadMessages"`
	Info              CategoryInfo `json:"categoryInfo"`
	ContinuationToken string       `json:"continuationToken"`
	Messages          []Message    `json:"messages"`
}

// CategoryInfo names a category; the client compares Type case-insensitively.
type CategoryInfo struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Image struct {
		URL string `json:"url"`
	} `json:"image"`
}

// Refresh fetches the session's current messages and advances its continuation token.
func (c *Client) Refresh(ctx context.Context) (*Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var session Session
	body := map[string]string{"sessionId": c.sessionID, "continuationToken": c.continuation}
	if _, err := request.Do(ctx, c.env.HTTPClient, c.src, http.MethodPost, c.env.ServiceURI.JoinPath("/api/v1.0/session/refresh"), body, &session, c.options()); err != nil {
		return nil, err
	}
	if session.ContinuationToken != "" {
		c.continuation = session.ContinuationToken
	}
	return &session, nil
}
