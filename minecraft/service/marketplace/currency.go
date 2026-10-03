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

// Balances returns the player's virtual currency balances.
func (c *Client) Balances(ctx context.Context) ([]Balance, error) {
	var result struct {
		Balances []Balance `json:"virtualCurrencyBalances"`
	}
	if _, err := c.do(ctx, http.MethodPost, c.endpoint("/api/v1.0/currencies/virtual/balances"), struct{}{}, &result, nil); err != nil {
		return nil, err
	}
	return result.Balances, nil
}
