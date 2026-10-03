package marketplace

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/service"
)

type fixedTokens struct{}

func (fixedTokens) ServiceToken(context.Context) (*service.Token, error) {
	return &service.Token{AuthorizationHeader: "MCToken synthetic", ValidUntil: time.Now().Add(time.Hour)}, nil
}

// Fixtures below are authored from the 26.30 client's parsers (SDL::SessionConfig::_initFromJson,
// SDL::ServiceResponseOfPage, StoreVisualStyle::_parseCustom, InventoryVerifier), not captured payloads.
const (
	sessionConfigFixture = `{"continuationToken":"","result":{"knownPages":{"home":"page-1"},"latestTextureVersion":"7",
"platformSkus":[{"contentType":"Minecoin","sku":"s","bigId":"b"}],"storeVersion":3,"userListsVersion":"u1",
"storeSearch":{"skinPackTerms":["skins"]},"badgePromoCountdownWindow":86400}}`
	pageFixture = `{"continuationToken":"","result":{"pageId":"page-1","pageName":"Home","inventoryVersion":"v1",
"sidebarLayoutType":"Default","buttons":[{"actionType":"Purchase","offerType":"PlatformOffer","offerId":"o1","ownership":"Owned"}],
"layout":[{"sectionName":"Main","rows":[{"telemetryId":"t1","controlId":"StoreRow",
"components":[{"type":"itemListComp","totalItems":12,"items":[{"images":[]}]}],
"queries":[{"queryContentTypes":["MarketplaceDurableCatalog_V1.2"],"itemLimit":12,"orTags":["new"],"notTags":["hidden"],"sortBy":"creationDate"}]}]}]}}`
	inventoryFixture = `{"result":{"inventory":{"entitlements":[{"id":"11111111-1111-1111-1111-111111111111","packId":"p","CreatorId":"c"}]},
"receipt":"eyJFbnRpdHlJZCI6ImUifQ=="}}`
	itemsFixture = `{"continuationToken":"next","result":[{"id":"a","title":{"neutral":"Alpha"},"creatorName":"Maker","price":320,
"images":[{"type":"Thumbnail","url":"https://cdn.example.test/a.png"}]},
{"id":"b","title":{"NEUTRAL":"Beta"},"price":{"listPrice":990,"currencyId":"Minecoin","saleInfo":{"salePrice":490,"discount":0.5}}}]}`
)

// newStore serves distinct store and entitlements origins and checks every request's service.
// The returned function closes both servers so transport failures can be tested.
func newStore(t *testing.T, handler http.HandlerFunc) (*Client, func()) {
	t.Helper()
	serve := func(serviceName string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			want := "store"
			switch r.URL.Path {
			case "/api/v1.0/player/inventory", "/api/v1.0/currencies/virtual/balances", "/api/v1.0/transaction/virtual":
				want = "entitlements"
			}
			if serviceName != want {
				t.Errorf("%s reached %s, want %s", r.URL.Path, serviceName, want)
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.Header.Get("Authorization") != "MCToken synthetic" {
				t.Error("request missing service token")
			}
			handler(w, r)
		}
	}
	store := httptest.NewTLSServer(serve("store"))
	entitlements := httptest.NewTLSServer(serve("entitlements"))
	closeServers := func() { store.Close(); entitlements.Close() }
	t.Cleanup(closeServers)
	env := &Environment{HTTPClient: store.Client()}
	owned := &EntitlementsEnvironment{HTTPClient: entitlements.Client()}
	discovery := service.Discovery{ServiceEnvironments: map[string]map[string]json.RawMessage{
		"store":        {"prod": json.RawMessage(`{"serviceUri":"` + store.URL + `"}`)},
		"entitlements": {"prod": json.RawMessage(`{"serviceUri":"` + entitlements.URL + `"}`)},
	}}
	for _, e := range []service.Environment{env, owned} {
		if err := discovery.Environment(e); err != nil {
			t.Fatal(err)
		}
	}
	client, err := env.New(fixedTokens{}, owned)
	if err != nil {
		t.Fatal(err)
	}
	return client, closeServers
}

// Every read decodes the reference schema with the reference method and path.
func TestStoreReadsDecodeTheReferenceSchema(t *testing.T) {
	var seen []string
	client, _ := newStore(t, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		switch r.URL.Path {
		case "/api/v1.0/session/config":
			if r.Header.Get("Session-Id") == "" {
				t.Error("session config without Session-Id")
			}
			_, _ = io.WriteString(w, sessionConfigFixture)
		case "/api/v1.0/currencies/virtual/balances":
			_, _ = io.WriteString(w, `{"result":{"virtualCurrencyBalances":[{"type":"Minecoin","amount":1500}]}}`)
		case "/api/v1.0/player/inventory":
			w.Header().Set("InventoryETag", "e1")
			_, _ = io.WriteString(w, inventoryFixture)
		case "/api/v1.0/inventory/refresh":
			_, _ = io.WriteString(w, `{"result":{"version":"v2"}}`)
		case "/api/v2.0/layout/pages/page-1":
			var state PageRequest
			_ = json.NewDecoder(r.Body).Decode(&state)
			if len(state.Entitlements) != 1 || state.InventoryVersion != "e1" {
				t.Errorf("page state = %+v", state)
			}
			w.Header().Set("X-UserLists-Version", "u2")
			_, _ = io.WriteString(w, pageFixture)
		case "/api/v2.0/layout/items":
			_, _ = io.WriteString(w, itemsFixture)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	ctx := context.Background()
	config, err := client.SessionConfig(ctx)
	if err != nil || config.PageID("home") != "page-1" || config.PageID("other") != "other" || config.PlatformSKUs[0].BigID != "b" {
		t.Fatalf("config = %+v err = %v", config, err)
	}
	balances, err := client.Balances(ctx)
	if err != nil || balances[0].Amount != 1500 {
		t.Fatalf("balances = %+v err = %v", balances, err)
	}
	inventory, err := client.Inventory(ctx)
	if err != nil || inventory.ETag != "e1" || inventory.Entitlements[0].CreatorID != "c" || inventory.Receipt == "" {
		t.Fatalf("inventory = %+v err = %v", inventory, err)
	}
	if version, err := client.RefreshInventory(ctx); err != nil || version != "v2" {
		t.Fatalf("refresh = %q err = %v", version, err)
	}
	page, err := client.Page(ctx, PageByID, config.PageID("home"), PageRequest{Entitlements: []string{inventory.Entitlements[0].ID}, InventoryVersion: inventory.ETag})
	if err != nil || page.HeaderListsVersion != "u2" || page.Buttons[0].Ownership != "Owned" {
		t.Fatalf("page = %+v err = %v", page, err)
	}
	row := page.Layout[0].Rows[0]
	if row.ControlID != "StoreRow" || row.Components[0].TotalItems != 12 || row.Queries[0].OrTags[0] != "new" {
		t.Fatalf("row = %+v", row)
	}
	items, next, err := client.ContinueRow(ctx, "t", "v1")
	if err != nil || next != "next" || items[0].Price.ListPrice != 320 || items[1].Price.Sale.SalePrice != 490 || items[1].Title.Neutral() != "Beta" {
		t.Fatalf("items = %+v next = %q err = %v", items, next, err)
	}
	want := []string{
		"GET /api/v1.0/session/config", "POST /api/v1.0/currencies/virtual/balances", "GET /api/v1.0/player/inventory?includeReceipt=true",
		"POST /api/v1.0/inventory/refresh", "POST /api/v2.0/layout/pages/page-1", "POST /api/v2.0/layout/items",
	}
	if strings.Join(seen, ",") != strings.Join(want, ",") {
		t.Fatalf("requests = %v", seen)
	}
}

// Malformed answers are errors, never empty successes, and service errors keep their status.
func TestStoreSurfacesDecodeAndServiceErrors(t *testing.T) {
	client, _ := newStore(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1.0/currencies/virtual/balances":
			_, _ = io.WriteString(w, `{"result":{"virtualCurrencyBalances":[{"type":"Minecoin","amount":"lots"}]}}`)
		case "/api/v1.0/player/inventory":
			_, _ = io.WriteString(w, `{"result":{"inventory":{"entitlements":[]}}}`)
		case "/api/v2.0/layout/items":
			_, _ = io.WriteString(w, `{"continuationToken":"x"}`)
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"code":"Denied","message":"no"}`)
		}
	})
	ctx := context.Background()
	if _, err := client.Balances(ctx); err == nil {
		t.Error("a non-numeric balance decoded")
	}
	if _, err := client.Inventory(ctx); err == nil {
		t.Error("an inventory without a receipt decoded")
	}
	if _, _, err := client.ContinueRow(ctx, "t", ""); err == nil {
		t.Error("a continuation without a result decoded")
	}
	var responseErr *service.ResponseError
	if _, err := client.SessionConfig(ctx); !errors.As(err, &responseErr) || responseErr.StatusCode != http.StatusForbidden {
		t.Errorf("session config err = %v", err)
	}
	if _, err := client.Page(ctx, PageByID, "../x", PageRequest{}); err == nil {
		t.Error("a path-changing page id was requested")
	}
}

// A purchase is sent exactly once whatever the answer, and each status maps to its outcome.
func TestPurchaseIsSentAtMostOnce(t *testing.T) {
	for status, want := range map[int]PurchaseOutcome{200: PurchaseSucceeded, 422: PurchasePriceMismatch, 412: PurchasePreconditionFailed, 503: PurchaseFailed} {
		var calls atomic.Int32
		var body purchaseBody
		client, _ := newStore(t, func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			_ = json.NewDecoder(r.Body).Decode(&body)
			w.Header().Set("InventoryETag", "e9")
			w.WriteHeader(status)
		})
		result, err := client.PurchaseVirtual(context.Background(), Purchase{OfferID: "o1", StoreID: "s1", Amount: 320, Tags: CustomTags{TitleID: "20CA2", Seq: 1}})
		if err != nil || result.Outcome != want || result.StatusCode != status || calls.Load() != 1 {
			t.Fatalf("status %d: result = %+v calls = %d err = %v", status, result, calls.Load(), err)
		}
		if body.VirtualCurrency.Type != CurrencyMinecoin || body.VirtualCurrency.Amount != "320" || body.CustomTags.TitleID != "20CA2" {
			t.Fatalf("purchase body = %+v", body)
		}
	}
	client, closeServers := newStore(t, func(http.ResponseWriter, *http.Request) {})
	closeServers()
	if result, err := client.PurchaseVirtual(context.Background(), Purchase{OfferID: "o1", Amount: 1}); err != nil || result.Outcome != PurchaseUnknown {
		t.Fatalf("unreachable service: result = %+v err = %v", result, err)
	}
}

// Redirects must neither replay a purchase nor turn a redirected read into a successful purchase.
func TestPurchaseDoesNotFollowRedirects(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		var calls atomic.Int32
		client, _ := newStore(t, func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			if r.URL.Path == "/api/v1.0/transaction/virtual" {
				http.Redirect(w, r, "/redirected", status)
				return
			}
			w.WriteHeader(http.StatusOK)
		})
		result, err := client.PurchaseVirtual(context.Background(), Purchase{OfferID: "o1", Amount: 320})
		if err != nil || result.Outcome != PurchaseFailed || result.StatusCode != status || calls.Load() != 1 {
			t.Errorf("status %d: result = %+v calls = %d err = %v", status, result, calls.Load(), err)
		}
	}
}

// The store never follows a redirect off its origin with the service token.
func TestStoreRefusesOffOriginRedirects(t *testing.T) {
	var leaked atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { leaked.Add(1) }))
	defer other.Close()
	client, _ := newStore(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
	})
	if _, err := client.SessionConfig(context.Background()); err == nil || leaked.Load() != 0 {
		t.Fatalf("redirect followed: err = %v leaked = %d", err, leaked.Load())
	}
	if _, err := client.Balances(context.Background()); err == nil || leaked.Load() != 0 {
		t.Fatalf("entitlements redirect followed: err = %v leaked = %d", err, leaked.Load())
	}
}

// Even the other discovered service is not an allowed redirect target.
func TestStoreRefusesRedirectsBetweenServices(t *testing.T) {
	var target, expectedPath string
	var leaked atomic.Int32
	client, _ := newStore(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != expectedPath {
			leaked.Add(1)
		}
		http.Redirect(w, r, target, http.StatusFound)
	})
	expectedPath = "/api/v1.0/session/config"
	target = client.entitlements.endpoint("/api/v1.0/player/inventory").String()
	if _, err := client.SessionConfig(context.Background()); err == nil {
		t.Fatal("store redirected to entitlements")
	}
	expectedPath = "/api/v1.0/player/inventory"
	target = client.store.endpoint("/api/v1.0/session/config").String()
	if _, err := client.Inventory(context.Background()); err == nil {
		t.Fatal("entitlements redirected to store")
	}
	if leaked.Load() != 0 {
		t.Fatalf("followed %d redirects across service origins", leaked.Load())
	}
}

// Both services must be discovered and have valid HTTPS origins before a client is built.
func TestStoreRequiresBothEnvironments(t *testing.T) {
	valid, _ := url.Parse("https://service.example.test")
	for _, raw := range []string{"", "http://service.example.test", "https:///missing-host", "https://user@service.example.test"} {
		invalid, _ := url.Parse(raw)
		for _, invalidStore := range []bool{false, true} {
			store := new(Environment)
			owned := new(EntitlementsEnvironment)
			store.ServiceURI, owned.ServiceURI = valid, valid
			if invalidStore {
				store.ServiceURI = invalid
			} else {
				owned.ServiceURI = invalid
			}
			if _, err := store.New(fixedTokens{}, owned); err == nil {
				t.Errorf("accepted invalid URI %q (store=%v)", raw, invalidStore)
			}
		}
	}
	store := new(Environment)
	store.ServiceURI = valid
	if _, err := store.New(fixedTokens{}, nil); err == nil {
		t.Error("accepted missing entitlements environment")
	}
}

// A row query maps onto a quoted PlayFab filter, and unsupported members are refused.
func TestQuerySearchFilter(t *testing.T) {
	filter, ok := Query{ContentTypes: []string{"A"}, OrTags: []string{"x", "o'k"}, NotTags: []string{"h"}, ItemLimit: 80, SortDirection: "ASC"}.SearchFilter()
	if !ok || filter.Filter != "ContentType eq 'A' and (Tags/any(t: t eq 'x') or Tags/any(t: t eq 'o''k')) and not Tags/any(t: t eq 'h')" ||
		filter.Count != maxSearchCount || filter.OrderBy != "startDate asc" {
		t.Fatalf("filter = %+v ok = %v", filter, ok)
	}
	if _, ok := (Query{RarityFilters: []string{"epic"}}).SearchFilter(); ok {
		t.Fatal("a rarity query was mapped")
	}
}
