package marketplace

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/sandertv/gophertunnel/minecraft/service/internal"
)

// CurrencyMinecoin is the virtual currency the reference client purchases with.
const CurrencyMinecoin = "Minecoin"

// Purchase is one Minecoin purchase of an offer at the price the player confirmed.
type Purchase struct {
	OfferID             string
	StoreID             string
	Amount              uint64
	UnitDurationSeconds *uint64 // subscription offers only
	Tags                CustomTags
}

// CustomTags is the client telemetry block every purchase carries.
type CustomTags struct {
	ClientID        string `json:"ClientId"`
	DeviceSessionID string `json:"DeviceSessionId"`
	CorrelationID   string `json:"CorrelationId"`
	TitleID         string `json:"TitleId"`
	BuildPlat       int    `json:"BuildPlat"`
	EditionType     string `json:"editionType"`
	Seq             uint32 `json:"Seq"`
	DnAPlat         string `json:"DnAPlat,omitempty"`
	Xuid            string `json:"Xuid,omitempty"`
}

// PurchaseOutcome is how the service answered a purchase.
type PurchaseOutcome int

const (
	// PurchaseUnknown means no answer arrived; the purchase may or may not have happened.
	PurchaseUnknown PurchaseOutcome = iota
	PurchaseSucceeded
	PurchaseFailed
	PurchasePriceMismatch      // HTTP 422
	PurchasePreconditionFailed // HTTP 412
)

// PurchaseResult is the answer to one purchase.
type PurchaseResult struct {
	Outcome       PurchaseOutcome
	StatusCode    int
	InventoryETag string
}

type purchaseBody struct {
	VirtualCurrency struct {
		Type   string `json:"Type"`
		Amount string `json:"Amount"`
	} `json:"VirtualCurrency"`
	OfferID               string     `json:"OfferId"`
	StoreID               string     `json:"StoreId"`
	CustomTags            CustomTags `json:"CustomTags"`
	UnitDurationInSeconds *uint64    `json:"UnitDurationInSeconds,omitempty"`
}

// PurchaseVirtual buys an offer with Minecoins. The request is sent at most once and never retried.
// An error means it was not sent; once sent, the outcome is in the result, PurchaseUnknown when no
// answer arrived.
func (c *Client) PurchaseVirtual(ctx context.Context, p Purchase) (PurchaseResult, error) {
	if p.OfferID == "" || p.Amount == 0 {
		return PurchaseResult{}, errors.New("service/marketplace: purchase needs an offer and a positive amount")
	}
	body := purchaseBody{OfferID: p.OfferID, StoreID: p.StoreID, CustomTags: p.Tags, UnitDurationInSeconds: p.UnitDurationSeconds}
	body.VirtualCurrency.Type = CurrencyMinecoin
	body.VirtualCurrency.Amount = strconv.FormatUint(p.Amount, 10)
	encoded, err := json.Marshal(body)
	if err != nil {
		return PurchaseResult{}, fmt.Errorf("encode purchase: %w", err)
	}
	target := c.entitlements.endpoint("/api/v1.0/transaction/virtual")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(encoded))
	if err != nil {
		return PurchaseResult{}, fmt.Errorf("make request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", internal.UserAgent)
	token, err := c.entitlements.src.ServiceToken(ctx)
	if err != nil {
		return PurchaseResult{}, fmt.Errorf("request service token: %w", err)
	}
	token.SetAuthHeader(req)
	// Redirects can replay the purchase body or turn the response into an unrelated GET.
	client := *c.entitlements.http
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return PurchaseResult{Outcome: PurchaseUnknown}, nil
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	result := PurchaseResult{StatusCode: resp.StatusCode, InventoryETag: resp.Header.Get("InventoryETag")}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode <= 299:
		result.Outcome = PurchaseSucceeded
	case resp.StatusCode == http.StatusUnprocessableEntity:
		result.Outcome = PurchasePriceMismatch
	case resp.StatusCode == http.StatusPreconditionFailed:
		result.Outcome = PurchasePreconditionFailed
	default:
		result.Outcome = PurchaseFailed
	}
	return result, nil
}
