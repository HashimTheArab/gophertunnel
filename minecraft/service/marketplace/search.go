package marketplace

import (
	"strings"

	"github.com/df-mc/go-playfab/v2/catalog"
)

// maxSearchCount is PlayFab's per-page search limit.
const maxSearchCount = 50

// SearchFilter maps the query onto a PlayFab catalog search, or reports false when it uses members
// with no known catalog field (rarity, piece type or creator filters). The reference client's exact
// search request is unconfirmed; this uses PlayFab's documented OData filter over ContentType, Tags
// and Id.
func (q Query) SearchFilter() (catalog.SearchFilter, bool) {
	if len(q.RarityFilters) > 0 || len(q.PieceTypeFilters) > 0 || len(q.CreatorIDs) > 0 ||
		len(q.Exclusions.CreatorIDs) > 0 || len(q.Exclusions.PieceTypeFilters) > 0 {
		return catalog.SearchFilter{}, false
	}
	var clauses []string
	if len(q.ContentTypes) > 0 {
		clauses = append(clauses, anyOf("ContentType eq %s", q.ContentTypes))
	}
	if len(q.OrTags) > 0 {
		clauses = append(clauses, anyOf("Tags/any(t: t eq %s)", q.OrTags))
	}
	for _, tag := range q.AndTags {
		clauses = append(clauses, "Tags/any(t: t eq "+literal(tag)+")")
	}
	for _, tag := range q.NotTags {
		clauses = append(clauses, "not Tags/any(t: t eq "+literal(tag)+")")
	}
	if len(q.ProductIDs) > 0 {
		clauses = append(clauses, anyOf("Id eq %s", q.ProductIDs))
	}
	for _, id := range q.Exclusions.ProductIDs {
		clauses = append(clauses, "Id ne "+literal(id))
	}
	sortBy, direction := q.SortBy, strings.ToLower(q.SortDirection)
	if sortBy == "" {
		sortBy = "startDate"
	}
	if direction != "asc" {
		direction = "desc"
	}
	count := q.ItemLimit
	if count <= 0 || (q.TopCount > 0 && q.TopCount < count) {
		count = q.TopCount
	}
	return catalog.SearchFilter{
		Count:   min(max(count, 0), maxSearchCount),
		Filter:  strings.Join(clauses, " and "),
		OrderBy: sortBy + " " + direction,
		Term:    q.SearchString,
	}, true
}

func anyOf(format string, values []string) string {
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = strings.Replace(format, "%s", literal(value), 1)
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, " or ") + ")"
}

// literal quotes s as an OData string literal.
func literal(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
