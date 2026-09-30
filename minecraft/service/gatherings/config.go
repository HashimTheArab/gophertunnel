package gatherings

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/service/internal/request"
)

// ConfigQuery identifies the client asking for the public gathering configuration.
type ConfigQuery struct {
	ClientVersion     string
	ClientPlatform    string
	ClientSubPlatform string
}

// GatheringConfig is one live event from the public gathering configuration.
type GatheringConfig struct {
	ID                string        `json:"gatheringId"`
	Start             Time          `json:"startTimeUtc"`
	End               Time          `json:"endTimeUtc"`
	Title             string        `json:"title"`
	Description       string        `json:"description"`
	RouteToServersTab bool          `json:"shouldRouteToServerTab"`
	Venue             ExternalVenue `json:"externalVenue"`
	Segments          []Segment     `json:"segments"`
}

// ExternalVenue is the server a gathering sends players to.
type ExternalVenue struct {
	NetherNetID     string `json:"netherNetId"`
	ServerIPAddress string `json:"serverIpAddress"`
	ServerPort      int    `json:"serverPort"`
}

// RakNetAddress returns the venue's host:port, or false when it names no RakNet server.
func (v ExternalVenue) RakNetAddress() (string, bool) {
	if v.ServerIPAddress == "" || v.ServerPort <= 0 || v.ServerPort > 65535 {
		return "", false
	}
	return net.JoinHostPort(v.ServerIPAddress, strconv.Itoa(v.ServerPort)), true
}

// Segment is one phase of a gathering with the start-screen UI shown during it.
type Segment struct {
	Type  string    `json:"segmentType"`
	Start Time      `json:"startTimeUtc"`
	End   Time      `json:"endTimeUtc"`
	UI    SegmentUI `json:"ui"`
}

// SegmentUI is the start-screen presentation of a segment.
type SegmentUI struct {
	BadgeImage             string `json:"badgeImage"`
	BodyImage              string `json:"bodyImage"`
	EventImage             string `json:"eventImage"`
	ActionButtonText       string `json:"actionButtonText"`
	InfoButtonText         string `json:"infoButtonText"`
	ActionButtonURL        string `json:"actionButtonUrl"`
	InfoButtonURL          string `json:"infoButtonUrl"`
	HeaderText             string `json:"headerText"`
	TitleText              string `json:"titleText"`
	BodyText               string `json:"bodyText"`
	StartScreenButtonText  string `json:"startScreenButtonText"`
	CaptionText            string `json:"captionText"`
	CaptionCountdown       bool   `json:"captionIncludesCountdown"`
	CaptionBackgroundColor string `json:"captionBackgroundColor"`
	CaptionForegroundColor string `json:"captionForegroundColor"`
}

// Time is a UTC timestamp the service sends as an RFC 3339 string; an empty string is the zero time.
type Time struct{ time.Time }

// UnmarshalJSON decodes an RFC 3339 string.
func (t *Time) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == "" {
		t.Time = time.Time{}
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return fmt.Errorf("service/gatherings: parse time %q: %w", s, err)
	}
	t.Time = parsed
	return nil
}

// PublicConfig returns the live events the start screen advertises.
func (c *Client) PublicConfig(ctx context.Context, query ConfigQuery) ([]GatheringConfig, error) {
	target := c.env.ServiceURI.JoinPath("/api/v1.0/config/public")
	values := target.Query()
	values.Set("clientVersion", query.ClientVersion)
	values.Set("clientPlatform", query.ClientPlatform)
	values.Set("clientSubPlatform", query.ClientSubPlatform)
	target.RawQuery = values.Encode()
	var configs []GatheringConfig
	if _, err := request.Do(ctx, c.client, c.src, http.MethodGet, target, nil, &configs, request.Options{}); err != nil {
		return nil, err
	}
	return configs, nil
}
