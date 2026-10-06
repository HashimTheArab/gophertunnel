package playermessaging

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/service/internal/request"
)

// Message is one player message; Surface places it (PlayButton, MarketplaceButton, InboxMessage,
// LoginAnnouncement, ToastNotification, ...) and Template names its layout.
type Message struct {
	ID             string            `json:"id"`
	InstanceID     string            `json:"instanceId"`
	IsControl      bool              `json:"isControl"`
	ReportID       string            `json:"reportId"`
	Sender         string            `json:"sender"`
	Surface        string            `json:"surface"`
	Template       string            `json:"template"`
	AllowInGame    bool              `json:"allowInGame"`
	Text           MessageText       `json:"messageText"`
	Buttons        map[string]Button `json:"buttons"`
	Images         map[string]Image  `json:"images"`
	InboxCategory  string            `json:"inboxCategory"`
	DateReceived   string            `json:"dateReceived"`
	ExpirationDate string            `json:"expirationDate"`
	Status         string            `json:"status"`
	Items          []MessageItem     `json:"messageItemList"`
	Style          json.RawMessage   `json:"style"`
}

// MessageText is a message's header and body.
type MessageText struct {
	Header string `json:"header"`
	Body   string `json:"body"`
}

// Button is one message button; Action says how Link opens.
type Button struct {
	ID          string `json:"id,omitempty"`
	Text        string `json:"text"`
	Description string `json:"description"`
	Link        string `json:"link"`
	Action      string `json:"action"`
}

// Image is one message image.
type Image struct {
	ID   string `json:"id,omitempty"`
	URL  string `json:"url"`
	Size struct {
		Width  int `json:"width"`
		Height int `json:"height"`
	} `json:"imageSize"`
}

// MessageItem is one entry of a multi-item message.
type MessageItem struct {
	Button       Button          `json:"button"`
	Image        Image           `json:"image"`
	SaleBanner   json.RawMessage `json:"saleBanner"`
	SubTitle     string          `json:"subTitle"`
	FooterCTA    json.RawMessage `json:"FooterCTA"`
	FooterHeader string          `json:"footerHeader"`
	FooterBody   string          `json:"footerBody"`
}

// EventType is a message interaction reported to the service.
type EventType string

const (
	EventClick             EventType = "Click"
	EventDismiss           EventType = "Dismiss"
	EventDelete            EventType = "Delete"
	EventImpression        EventType = "Impression"
	EventControlImpression EventType = "ControlImpression"
	EventSubmit            EventType = "Submit"
	EventSettingUpdate     EventType = "SettingUpdate"
	EventReadAll           EventType = "ReadAll"
	EventDeleteAllRead     EventType = "DeleteAllRead"
)

// Event is one message interaction; InstanceID and ReportID name the message it is about.
type Event struct {
	Type       EventType
	Time       time.Time
	InstanceID string
	ReportID   string
	ButtonID   string
}

type eventEntry struct {
	EventDateTime string    `json:"eventDateTime"`
	EventType     EventType `json:"eventType"`
	SessionID     string    `json:"sessionId"`
	InstanceID    string    `json:"instanceId,omitempty"`
	ReportID      string    `json:"reportId,omitempty"`
	ButtonID      string    `json:"buttonId,omitempty"`
}

// ReportEvents posts message interactions for this session.
func (c *Client) ReportEvents(ctx context.Context, events ...Event) error {
	if len(events) == 0 {
		return errors.New("service/playermessaging: no events")
	}
	entries := make([]eventEntry, 0, len(events))
	for _, event := range events {
		if event.Type == "" {
			return errors.New("service/playermessaging: event has no type")
		}
		at := event.Time
		if at.IsZero() {
			at = time.Now()
		}
		entries = append(entries, eventEntry{
			EventDateTime: at.UTC().Format("2006-01-02T15:04:05.000Z"),
			EventType:     event.Type, SessionID: c.sessionID,
			InstanceID: event.InstanceID, ReportID: event.ReportID, ButtonID: event.ButtonID,
		})
	}
	body := map[string]any{"SessionId": c.sessionID, "continuationToken": c.current(), "events": entries}
	_, err := request.Do(ctx, c.env.HTTPClient, c.src, http.MethodPost, c.env.ServiceURI.JoinPath("/api/v1.0/messages/event"), body, nil, c.options())
	return err
}
