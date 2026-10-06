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
	ID                string    `json:"id"`
	PageID            string    `json:"pageId"`
	PageName          string    `json:"pageName"`
	InventoryETag     string    `json:"inventoryETag"`
	InventoryVersion  string    `json:"inventoryVersion"`
	UserListsVersion  string    `json:"userListsVersion"`
	SidebarLayoutType string    `json:"sidebarLayoutType"`
	PageRefresh       bool      `json:"pageRefresh"`
	RecentlyViewed    bool      `json:"addToRecentlyViewed"`
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

// Row is one layout row. A curated row lists its offers inline in an item list component.
type Row struct {
	TelemetryID string      `json:"telemetryId"`
	ControlID   string      `json:"controlId"` // visual factory, such as StoreRow, HeroRow or PromoBanner
	Components  []Component `json:"components"`
	Queries     []Query     `json:"queries"`
}

// Component returns the row's first component of the given type, or nil.
func (r *Row) Component(kind string) *Component {
	for i := range r.Components {
		if r.Components[i].Type == kind {
			return &r.Components[i]
		}
	}
	return nil
}

// Component returns the first component of the given type on any row of the page, or nil.
func (p *Page) Component(kind string) *Component {
	for i := range p.Layout {
		for j := range p.Layout[i].Rows {
			if component := p.Layout[i].Rows[j].Component(kind); component != nil {
				return component
			}
		}
	}
	return nil
}

// ItemList returns the row's item list component, paged or not, or nil.
func (r *Row) ItemList() *Component {
	for i := range r.Components {
		if t := r.Components[i].Type; t == ComponentItemList || t == ComponentPagedItemList {
			return &r.Components[i]
		}
	}
	return nil
}

// Title returns the row's header text, or "" for a row without a header.
func (r *Row) Title() string {
	header := r.Component(ComponentHeader)
	if header == nil {
		return ""
	}
	if header.HeaderText != "" {
		return header.HeaderText
	}
	if header.Text != nil {
		return header.Text.Value
	}
	return ""
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

// KnownPage loads the page config maps name to; an unknown name fails with [ErrUnknownPage]
// before any request.
func (c *Client) KnownPage(ctx context.Context, config *SessionConfig, name string, state PageRequest) (*Page, error) {
	id, err := config.PageID(name)
	if err != nil {
		return nil, err
	}
	return c.Page(ctx, PageByID, id, state)
}

// Page loads a layout page by id, from [SessionConfig.PageID] or [Link.PageID]. An offer's detail
// page is loaded with [PageByProductID] and the offer id.
func (c *Client) Page(ctx context.Context, kind PageKind, id string, state PageRequest) (*Page, error) {
	return c.page(ctx, kind, id, state)
}

// page posts body to a layout page endpoint.
func (c *Client) page(ctx context.Context, kind PageKind, id string, body any) (*Page, error) {
	prefix, ok := kind.prefix()
	if !ok || id == "" || strings.ContainsAny(id, "/?#") || id == "." || id == ".." {
		return nil, errors.New("service/marketplace: invalid page request")
	}
	var page Page
	resp, err := c.store.do(ctx, http.MethodPost, c.store.endpoint(prefix, id), body, &page, nil)
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
	page.HeaderInventoryETag = resp.Header.Get(inventoryETagHeader)
	c.noteInventoryVersion(page.HeaderInventoryETag)
	page.HeaderListsVersion = resp.Header.Get("X-UserLists-Version")
	c.noteListsVersion(page.HeaderListsVersion)
	return &page, nil
}
