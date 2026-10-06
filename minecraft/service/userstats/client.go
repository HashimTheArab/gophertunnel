// Package userstats reads Xbox Live statistics using the batch read API used by Bedrock.
package userstats

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/service"
	"github.com/sandertv/gophertunnel/minecraft/service/internal/request"
)

const (
	endpoint  = "https://userstats.xboxlive.com/batch?operation=read"
	userAgent = "XboxServicesAPI/2025.10.20251000.0"
)

// Client reads statistics through an HTTP client that supplies Xbox Live authentication.
type Client struct {
	client *http.Client
	// Language is the locale used for service responses; NewClient defaults to American English.
	Language string
}

// NewClient uses client for authenticated requests; nil selects http.DefaultClient.
func NewClient(client *http.Client) *Client {
	if client == nil {
		client = http.DefaultClient
	}
	return &Client{client: client, Language: "en-US"}
}

// RequestedStatistics selects the named statistics belonging to one service configuration.
type RequestedStatistics struct {
	ServiceConfigID uuid.UUID `json:"scid"`
	Names           []string  `json:"requestedstats"`
}

// UserStatistics contains the statistics returned for one Xbox user.
type UserStatistics struct {
	XUID                  string              `json:"xuid"`
	ServiceConfigurations []ServiceStatistics `json:"scids"`
}

// ServiceStatistics groups statistics under their service configuration.
type ServiceStatistics struct {
	ServiceConfigID uuid.UUID   `json:"scid"`
	Statistics      []Statistic `json:"stats"`
}

// Statistic preserves the service's type and value without rounding numeric text.
type Statistic struct {
	Name  string          `json:"statname"`
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}

// Batch reads every requested user and configuration in one request, preserving request order.
func (c *Client) Batch(ctx context.Context, xuids []string, statistics []RequestedStatistics) ([]UserStatistics, error) {
	if len(xuids) == 0 || len(statistics) == 0 {
		return nil, errors.New("service/userstats: empty batch request")
	}
	for _, xuid := range xuids {
		if _, err := strconv.ParseUint(xuid, 10, 64); err != nil {
			return nil, errors.New("service/userstats: invalid user ID")
		}
	}
	for _, group := range statistics {
		if group.ServiceConfigID == uuid.Nil || len(group.Names) == 0 {
			return nil, errors.New("service/userstats: empty statistics selection")
		}
	}
	body, err := json.Marshal(struct {
		Users      []string              `json:"requestedusers"`
		Statistics []RequestedStatistics `json:"requestedscids"`
	}{xuids, statistics})
	if err != nil {
		return nil, fmt.Errorf("encode statistics request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-xbl-contract-version", "1")
	req.Header.Set("Accept-Language", c.Language)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &service.ResponseError{StatusCode: resp.StatusCode, Status: http.StatusText(resp.StatusCode)}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, request.MaxBody+1))
	if err != nil {
		return nil, fmt.Errorf("read statistics response: %w", err)
	}
	if len(data) > request.MaxBody {
		return nil, errors.New("service/userstats: response too large")
	}
	var result struct {
		Users []UserStatistics `json:"users"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("decode statistics response: %w", err)
	}
	if result.Users == nil {
		return nil, errors.New("service/userstats: response has no users")
	}
	return result.Users, nil
}
