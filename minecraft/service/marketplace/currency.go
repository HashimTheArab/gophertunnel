package marketplace

import (
	"context"
	"net/http"
)

// CurrencyPlayStationToken is the balance type of PlayStation tokens; every other type is Minecoins.
const CurrencyPlayStationToken = "PlayStationToken"

// Balance is one virtual currency balance.
type Balance struct {
	Type   string `json:"type"`
	Amount int64  `json:"amount"`
}

// Balances returns the player's virtual currency balances. Like the game, it sends an empty
// inventory version.
func (c *Client) Balances(ctx context.Context) ([]Balance, error) {
	var result struct {
		Balances []Balance `json:"virtualCurrencyBalances"`
	}
	if _, err := c.entitlements.do(ctx, http.MethodPost, c.entitlements.endpoint("/api/v1.0/currencies/virtual/balances"), struct{}{}, &result,
		http.Header{inventoryETagHeader: {""}}); err != nil {
		return nil, err
	}
	return result.Balances, nil
}
