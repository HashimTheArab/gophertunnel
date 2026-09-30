package marketplace

import (
	"context"
	"encoding/json"
	"net/http"
)

// Inventory is the player's owned content with the signed receipt the client verifies.
type Inventory struct {
	Entitlements       []Entitlement
	Receipt            string          // base64 receipt naming each entitlement's content key
	ThirdPartyReceipts json.RawMessage // kept undecoded
	ETag               string          // the InventoryETag the answer carried
}

// Entitlement is one owned content item; ID is the offer id pages and catalog items use.
type Entitlement struct {
	ID             string          `json:"id"`
	PackID         string          `json:"packId"`
	Ownership      json.RawMessage `json:"ownership"`
	Marketplace    json.RawMessage `json:"marketplace"`
	CreatorID      string          `json:"CreatorId"`
	Amount         json.RawMessage `json:"amount"`
	ExpirationDate string          `json:"expirationDate"`
}

// Inventory returns the player's entitlements; the result must carry both inventory and receipt.
func (c *Client) Inventory(ctx context.Context) (*Inventory, error) {
	var result struct {
		Inventory *struct {
			Entitlements []Entitlement `json:"entitlements"`
		} `json:"inventory"`
		Receipt            *string         `json:"receipt"`
		ThirdPartyReceipts json.RawMessage `json:"thirdPartyReceipts"`
	}
	target := c.endpoint("/api/v1.0/player/inventory")
	target.RawQuery = "includeReceipt=true"
	resp, err := c.do(ctx, http.MethodGet, target, nil, &result, nil)
	if err != nil {
		return nil, err
	}
	if result.Inventory == nil || result.Receipt == nil {
		return nil, errMissing("inventory result lacks inventory or receipt")
	}
	return &Inventory{
		Entitlements:       result.Inventory.Entitlements,
		Receipt:            *result.Receipt,
		ThirdPartyReceipts: result.ThirdPartyReceipts,
		ETag:               resp.Header.Get("InventoryETag"),
	}, nil
}

// RefreshInventory asks the service to rebuild the player's inventory and returns its new version.
func (c *Client) RefreshInventory(ctx context.Context) (string, error) {
	var result struct {
		Version *string `json:"version"`
	}
	if _, err := c.do(ctx, http.MethodPost, c.endpoint("/api/v1.0/inventory/refresh"), struct{}{}, &result, nil); err != nil {
		return "", err
	}
	if result.Version == nil {
		return "", errMissing("inventory refresh lacks a version")
	}
	return *result.Version, nil
}
