package gatherings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/service"
	"github.com/sandertv/gophertunnel/minecraft/service/internal"
	"github.com/sandertv/gophertunnel/minecraft/service/internal/request"
)

// PlayerCountsRefreshInterval is the minimum interval between player-count requests in Bedrock.
const PlayerCountsRefreshInterval = 5 * time.Minute

// ExperiencePlayerCount is the current population of an experience. A nil count is unavailable.
type ExperiencePlayerCount struct {
	ExperienceID uuid.UUID `json:"experienceId"`
	PlayerCount  *int64    `json:"playerCount"`
}

// PlayerCounts returns all experience populations, refreshing at most once per interval.
// Failed refreshes return the previous counts and an error; cache hits return the previous counts.
func (c *Client) PlayerCounts(ctx context.Context) ([]ExperiencePlayerCount, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.countsMu.Lock()
	now := time.Now()
	if c.countsNow != nil {
		now = c.countsNow()
	}
	if !c.countsRequested.IsZero() && now.Sub(c.countsRequested) < PlayerCountsRefreshInterval {
		counts := clonePlayerCounts(c.counts)
		c.countsMu.Unlock()
		return counts, nil
	}
	c.countsRequested = now
	c.countsMu.Unlock()

	counts, err := c.fetchPlayerCounts(ctx)
	c.countsMu.Lock()
	defer c.countsMu.Unlock()
	if err == nil {
		c.counts = counts
	}
	return clonePlayerCounts(c.counts), err
}

// fetchPlayerCounts requests the shared population snapshot without per-experience requests.
func (c *Client) fetchPlayerCounts(ctx context.Context) ([]ExperiencePlayerCount, error) {
	target := c.env.ServiceURI.JoinPath("/api/v2.0/dataquery/playercounts")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", internal.UserAgent)
	token, err := c.src.ServiceToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("request service token: %w", err)
	}
	token.SetAuthHeader(req)
	response, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, &service.ResponseError{StatusCode: response.StatusCode, Status: http.StatusText(response.StatusCode)}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, request.MaxBody+1))
	if err != nil {
		return nil, fmt.Errorf("read player counts: %w", err)
	}
	if len(data) > request.MaxBody {
		return nil, errors.New("service/gatherings: player counts response too large")
	}
	var envelope internal.Result[[]json.RawMessage]
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("decode player counts: %w", err)
	}
	if envelope.Data == nil {
		return nil, errors.New("service/gatherings: player counts response has no result")
	}
	counts := make([]ExperiencePlayerCount, 0, len(envelope.Data))
	for _, raw := range envelope.Data {
		var count ExperiencePlayerCount
		if json.Unmarshal(raw, &count) == nil && count.ExperienceID != uuid.Nil {
			counts = append(counts, count)
		}
	}
	return counts, nil
}

// clonePlayerCounts keeps callers from changing the cached slice or its optional values.
func clonePlayerCounts(counts []ExperiencePlayerCount) []ExperiencePlayerCount {
	if counts == nil {
		return nil
	}
	copied := append(make([]ExperiencePlayerCount, 0, len(counts)), counts...)
	for i := range copied {
		if copied[i].PlayerCount != nil {
			value := *copied[i].PlayerCount
			copied[i].PlayerCount = &value
		}
	}
	return copied
}
