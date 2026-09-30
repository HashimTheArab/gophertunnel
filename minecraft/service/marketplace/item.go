package marketplace

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// Item is a catalog item as the store service lists it for a row continuation.
type Item struct {
	ID           string          `json:"id"`
	ContentType  string          `json:"contentType"`
	Title        Localized       `json:"title"`
	Description  Localized       `json:"description"`
	Tags         []string        `json:"tags"`
	Platforms    []string        `json:"platforms"`
	Images       []Image         `json:"images"`
	StartDate    string          `json:"startDate"`
	CreationDate string          `json:"creationDate"`
	CreatorName  string          `json:"creatorName"`
	StoreID      string          `json:"storeId"`
	Ownership    json.RawMessage `json:"ownership"`
	Purchasable  *bool           `json:"purchasable"`
	Price        *Price          `json:"price"`
	PackType     string          `json:"packType"`
	PlayFabSKU   string          `json:"playFabSku"`
}

// Localized is a text keyed by locale; "neutral" is the fallback.
type Localized map[string]string

// Neutral returns the neutral text.
func (l Localized) Neutral() string {
	for key, value := range l {
		if strings.EqualFold(key, "neutral") {
			return value
		}
	}
	return ""
}

// Image is one catalog image; Type is Thumbnail, Banner or Icon.
type Image struct {
	ID                string `json:"id"`
	Tag               string `json:"tag"`
	Type              string `json:"type"`
	URL               string `json:"url"`
	URLWithResolution string `json:"urlWithResolution"`
}

// Price is an item's price: a bare amount, or a list price with its currency and optional sale.
type Price struct {
	ListPrice  uint64    `json:"listPrice"`
	CurrencyID string    `json:"currencyId"`
	Sale       *SaleInfo `json:"saleInfo"`
}

// SaleInfo is a limited-time sale price.
type SaleInfo struct {
	StartDate      string  `json:"startDate"`
	ExpirationDate string  `json:"expirationDate"`
	SalePrice      int64   `json:"salePrice"`
	StoreID        string  `json:"storeId"`
	Discount       float64 `json:"discount"`
	Category       string  `json:"category"`
}

// UnmarshalJSON decodes the price object or, as the reference client accepts, a bare amount.
func (p *Price) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] != '{' {
		var amount uint64
		if err := json.Unmarshal(b, &amount); err != nil {
			return err
		}
		*p = Price{ListPrice: amount}
		return nil
	}
	type plain Price
	return json.Unmarshal(b, (*plain)(p))
}

// ContinueRow loads the next items of a row from the continuation token a previous answer gave.
func (c *Client) ContinueRow(ctx context.Context, token, inventoryVersion string) ([]Item, string, error) {
	if token == "" {
		return nil, "", errors.New("service/marketplace: empty continuation token")
	}
	var envelope struct {
		ContinuationToken string  `json:"continuationToken"`
		Result            *[]Item `json:"result"`
	}
	body := map[string]string{"continuationToken": token, "inventoryVersion": inventoryVersion}
	data, _, err := c.raw(ctx, http.MethodPost, c.endpoint("/api/v2.0/layout/items"), body)
	if err != nil {
		return nil, "", err
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, "", err
	}
	if envelope.Result == nil {
		return nil, "", errMissing("row continuation lacks a result")
	}
	return *envelope.Result, envelope.ContinuationToken, nil
}
