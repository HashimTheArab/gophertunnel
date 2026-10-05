package marketplace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
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

// Known page names: the session-config knownPages keys the vanilla client requests pages by.
const (
	PageCoinScreen                            = "coinScreen"
	PageColorPicker                           = "colorPicker"
	PageCSBPacks                              = "csbPacks"
	PageDressingRoomClassicSkinsSearchHome    = "dressingRoomClassicSkinsSearchHome"
	PageDressingRoomClassicSkinsSearchResults = "dressingRoomClassicSkinsSearchResults"
	PageDressingRoomCoinScreen                = "dressingRoomCoinScreen"
	PageDressingRoomSearchHome                = "dressingRoomSearchHome"
	PageDressingRoomSearchResults             = "dressingRoomSearchResults"
	PageExpandedAppearanceView                = "expandedAppearanceView"
	PageFollowedCreators                      = "followedCreators"
	PageInventory                             = "inventory"
	PageInventorySearchHome                   = "inventorySearchHome"
	PageInventorySearchResults                = "inventorySearchResults"
	PagePauseMenu                             = "pauseMenu"
	PagePersonaProfile                        = "personaProfile"
	PagePersonaSubscriptionContent            = "personaSubscriptionContent"
	PageRealmsPlusPacks                       = "realmsPlusPacks"
	PageSearchHome                            = "searchHome"
	PageSearchResults                         = "searchResults"
	PageSkinsRoot                             = "skinsRoot"
	PageStoreRoot                             = "storeRoot" // the Marketplace home
	PageWishlist                              = "wishlist"
)

// ErrUnknownPage is returned for a page name the session config does not map to an id.
var ErrUnknownPage = errors.New("service/marketplace: unknown page")

// PageID returns the page id the config maps name to, or an error wrapping [ErrUnknownPage] that
// lists the known names. The service rejects any other id, so the name is never used as one.
func (c SessionConfig) PageID(name string) (string, error) {
	if id := c.KnownPages[name]; id != "" {
		return id, nil
	}
	names := slices.Sorted(maps.Keys(c.KnownPages))
	return "", fmt.Errorf("%w %q (known pages: %s)", ErrUnknownPage, name, strings.Join(names, ", "))
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
