package marketplace

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// PageKind selects the layout page endpoint; the reference client picks it from the navigation
// action that opened the page.
type PageKind int

const (
	PageByID PageKind = iota
	PageByProductID
	PageByPackID
)

func (k PageKind) prefix() (string, bool) {
	switch k {
	case PageByID:
		return "/api/v2.0/layout/pages/", true
	case PageByProductID:
		return "/api/v2.0/layout/pages/productId/", true
	case PageByPackID:
		return "/api/v2.0/layout/pages/packId/", true
	}
	return "", false
}

// PageRequest is the state a layout page is rendered against.
type PageRequest struct {
	Entitlements     []string `json:"entitlements"` // owned offer ids as 8-4-4-4-12 UUID strings
	InventoryVersion string   `json:"inventoryVersion"`
	ListVersion      string   `json:"listVersion"`
}

// Page is a server-driven store page.
type Page struct {
	PageID            string    `json:"pageId"`
	PageName          string    `json:"pageName"`
	InventoryETag     string    `json:"inventoryETag"`
	InventoryVersion  string    `json:"inventoryVersion"`
	UserListsVersion  string    `json:"userListsVersion"`
	SidebarLayoutType string    `json:"sidebarLayoutType"`
	PageRefresh       bool      `json:"pageRefresh"`
	Buttons           []Button  `json:"buttons"`
	Layout            []Section `json:"layout"`

	// Header values of the answer, which the next page request echoes back.
	HeaderInventoryETag string `json:"-"`
	HeaderListsVersion  string `json:"-"`
}

// Button is a page-level modal button.
type Button struct {
	ActionType string          `json:"actionType"`
	OfferType  string          `json:"offerType"`
	OfferID    string          `json:"offerId"`
	Ownership  string          `json:"ownership"`
	Text       json.RawMessage `json:"text"`
}

// Section is a titled group of rows.
type Section struct {
	Name string `json:"sectionName"`
	Rows []Row  `json:"rows"`
}

// Row is one layout row: components that present it and the catalog queries that fill it. Rows
// carry no offers; the client runs the queries against the catalog.
type Row struct {
	TelemetryID string      `json:"telemetryId"`
	ControlID   string      `json:"controlId"`
	Components  []Component `json:"components"`
	Queries     []Query     `json:"queries"`
}

// Component is one presentation component of a row, such as itemListComp or headerComp.
type Component struct {
	Type       string            `json:"type"`
	TotalItems int               `json:"totalItems"`
	Items      []json.RawMessage `json:"items"`
}

// Query is a catalog query a row is filled from.
type Query struct {
	ContentTypes          []string        `json:"queryContentTypes"`
	ItemLimit             int             `json:"itemLimit"`
	TopCount              int             `json:"topCount"`
	ClientPageSort        json.RawMessage `json:"clientPageSort"`
	SortBy                string          `json:"sortBy"`
	SortDirection         string          `json:"sortDirection"`
	SearchString          string          `json:"searchString"`
	OrTags                []string        `json:"orTags"`
	AndTags               []string        `json:"andTags"`
	NotTags               []string        `json:"notTags"`
	RarityFilters         []string        `json:"rarityFilters"`
	PieceTypeFilters      []string        `json:"pieceTypeFilters"`
	ProductIDs            []string        `json:"productIds"`
	CreatorIDs            []string        `json:"creatorIds"`
	Exclusions            QueryExclusions `json:"exclusions"`
	ExtraUpsellQueryTags  []string        `json:"extraUpsellQueryTags"`
	CarouselTimerDuration int             `json:"carouselTimerDuration"`
}

// QueryExclusions removes offers from a query's results.
type QueryExclusions struct {
	ProductIDs       []string `json:"productIds"`
	CreatorIDs       []string `json:"creatorIds"`
	PieceTypeFilters []string `json:"pieceTypeFilters"`
}

// maxRowQueries is the reference client's per-row query limit.
const maxRowQueries = 24

// Page loads a layout page by id; the id comes from [SessionConfig.PageID].
func (c *Client) Page(ctx context.Context, kind PageKind, id string, state PageRequest) (*Page, error) {
	prefix, ok := kind.prefix()
	if !ok || id == "" || strings.ContainsAny(id, "/?#") || id == "." || id == ".." {
		return nil, errors.New("service/marketplace: invalid page request")
	}
	var page Page
	resp, err := c.do(ctx, http.MethodPost, c.endpoint(prefix, id), state, &page, nil)
	if err != nil {
		return nil, err
	}
	for i := range page.Layout {
		for j := range page.Layout[i].Rows {
			if row := &page.Layout[i].Rows[j]; len(row.Queries) > maxRowQueries {
				row.Queries = row.Queries[:maxRowQueries]
			}
		}
	}
	page.HeaderInventoryETag = resp.Header.Get("InventoryETag")
	page.HeaderListsVersion = resp.Header.Get("X-UserLists-Version")
	return &page, nil
}
