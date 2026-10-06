package marketplace

import (
	"context"
	"encoding/json"
)

// Sort orders of a store search.
const (
	SortRelevance       = "Relevance"
	SortAlphabetical    = "Alphabetical"
	SortAverageRating   = "AverageRating"
	SortPrice           = "Price"
	SortStartDate       = "StartDate"
	SortInstalledStatus = "InstalledStatus"
)

// Sort directions of a store search.
const (
	SortDescending = "Desc"
	SortAscending  = "Asc"
)

// SearchRequest is a store search as the game's search screen sends it.
type SearchRequest struct {
	Search                  string `json:"search"`
	SortBy                  string `json:"sortBy"`        // one of the Sort constants; empty is SortRelevance
	SortDirection           string `json:"sortDirection"` // SortDescending or SortAscending; empty is SortDescending
	FilterPastRealmsPlus    bool   `json:"filterPastRealmsPlus"`
	FilterCurrentRealmsPlus bool   `json:"filterCurrentRealmsPlus"`
	// InstalledPackIDs is sent only with SortInstalledStatus.
	InstalledPackIDs []string `json:"installedPackIds,omitempty"`
	// Filters holds the range and tag filters by name; nil sends none.
	Filters map[string]json.RawMessage `json:"filters"`
}

// Search renders the session config's "searchResults" page for search. The results are the page's
// [ComponentPagedItemList]; [Client.ContinueRow] loads the rest from its continuation token.
func (c *Client) Search(ctx context.Context, config *SessionConfig, search SearchRequest, state PageRequest) (*Page, error) {
	id, err := config.PageID("searchResults")
	if err != nil {
		return nil, err
	}
	if search.SortBy == "" {
		search.SortBy = SortRelevance
	}
	if search.SortDirection == "" {
		search.SortDirection = SortDescending
	}
	if search.SortBy != SortInstalledStatus {
		search.InstalledPackIDs = nil
	}
	if search.Filters == nil {
		search.Filters = map[string]json.RawMessage{}
	}
	body := struct {
		PageRequest
		SearchRequest
	}{state, search}
	return c.page(ctx, PageByID, id, body)
}
