package marketplace

import (
	"context"
	"encoding/json"
	"net/http"
)

// SessionConfig is the store's per-session configuration.
type SessionConfig struct {
	BinaryURLs                map[string]string `json:"binaryUrls"`
	LatestTextureVersion      string            `json:"latestTextureVersion"`
	GlobalNotTags             []string          `json:"globalNotTags"`
	KnownPages                map[string]string `json:"knownPages"` // page name -> page id
	StoreFilters              []json.RawMessage `json:"storeFilters"`
	DressingRoomFilters       []json.RawMessage `json:"dressingRoomFilters"`
	StoreSearch               StoreSearch       `json:"storeSearch"`
	PlatformSKUs              []PlatformSKU     `json:"platformSkus"`
	StoreVersion              int               `json:"storeVersion"`
	FeedbackCharacterLimit    int               `json:"feedbackCharacterLimit"`
	UserListsVersion          string            `json:"userListsVersion"`
	BadgePromoCountdownWindow uint64            `json:"badgePromoCountdownWindow"`
	UpsellQueries             []json.RawMessage `json:"upsellQueries"`
}

// StoreSearch holds the search terms of each content category.
type StoreSearch struct {
	MashupPackTerms    []string `json:"mashupPackTerms"`
	SkinPackTerms      []string `json:"skinPackTerms"`
	TexturePackTerms   []string `json:"texturePackTerms"`
	WorldTemplateTerms []string `json:"worldTemplateTerms"`
}

// PlatformSKU maps a platform store SKU to a content type (Minecoin, Real, CoinBundle,
// MarketplacePass or PlaystationToken).
type PlatformSKU struct {
	ContentType string `json:"contentType"`
	SKU         string `json:"sku"`
	BigID       string `json:"bigId"`
}

// PageID returns the page id to request for a known page name; a name the config does not map is
// used as the id itself, as the client does.
func (c SessionConfig) PageID(name string) string {
	if id, ok := c.KnownPages[name]; ok && id != "" {
		return id
	}
	return name
}

// SessionConfig returns the store session configuration.
func (c *Client) SessionConfig(ctx context.Context) (*SessionConfig, error) {
	var config SessionConfig
	if _, err := c.store.do(ctx, http.MethodGet, c.store.endpoint("/api/v1.0/session/config"), nil, &config,
		http.Header{"Session-Id": {c.sessionID}}); err != nil {
		return nil, err
	}
	return &config, nil
}
