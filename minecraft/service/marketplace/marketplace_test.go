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

// Fixtures below are synthesized in the live service's shapes, not captured payloads.
const (
	sessionConfigFixture = `{"continuationToken":"","result":{"knownPages":{"storeRoot":"page-1","skinsRoot":"page-2"},"latestTextureVersion":"7",
"platformSkus":[{"contentType":"Minecoin","sku":"s","bigId":"b"}],"storeVersion":3,"userListsVersion":"u1",
"storeSearch":{"skinPackTerms":["skins"]},"badgePromoCountdownWindow":86400}}`
	pageFixture = `{"continuationToken":"","result":{"id":"p","pageId":"page-1","pageName":"Home","inventoryVersion":"v1",
"sidebarLayoutType":"Marketplace","buttons":[{"actionType":"Purchase","offerType":"PlatformOffer","offerId":"o1","ownership":"Owned"}],
"layout":[{"sectionName":"rows","rows":[
{"controlId":"Layout","components":[{"type":"topBarSearchComp","$type":"TopBarSearchComponent","isVisible":true,
 "linksToInfo":{"linksTo":"Search_SearchHome","linkType":"pageId"}}]},
{"telemetryId":"Row 0","controlId":"PromoBanner","components":[{"type":"promoBannerComp","factoryId":"banner_slim",
 "mainText":{"value":"Try it","replacements":[]},"mainImage":{"tag":"PromoBannerSlimAsset","type":"Screenshot","url":"https://cdn.example.test/m.gif"},
 "linksToInfo":{"linksTo":"Internal_Pass","linkType":"internal"}}],"queries":null},
{"telemetryId":"Row 1","controlId":"StoreRow","components":[
 {"type":"itemListComp","totalItems":9,"customStoreRowConfiguration":{"seeAllVisible":true,"maxOffers":8},
  "linksToInfo":{"linksTo":"MultiItemPage_p%7cPagedList_x","linkType":"pageId","screenTitle":{"value":"New"}},
  "items":[{"id":"a","title":"Alpha","description":"About","creatorName":"Maker","ownership":"NotOwned","flags":["New"],
   "thumbnail":{"tag":"Thumbnail","type":"Thumbnail","url":"https://cdn.example.test/a.png"},"rating":{"average":4.5,"totalCount":10},
   "price":{"listPrice":990,"currencyId":"c","virtualCurrencyType":"Minecoin"},"packIdentity":[{"type":"worldtemplate","uuid":"u","version":"1.0.0"}],
   "linksToInfo":{"linksTo":"ItemDetail_a","linkType":"pageId"}}]},
 {"type":"carouselComp"},{"type":"headerComp","headerText":"New","text":{"value":"New"}}]},
{"telemetryId":"Row 2","controlId":"NavButtonRow","components":[{"type":"navButtonListComp","buttons":[{"navButtonName":"Worlds",
 "image":"textures/ui/mashup_world","images":[{"type":"Unknown","localPath":"textures/ui/mashup_world"}],"linksToInfo":{"linksTo":"MultiItemPage_w","linkType":"pageId"}}]}]},
{"telemetryId":"t1","controlId":"StoreRow","components":[{"type":"itemListComp","totalItems":12,"items":null}],
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
	if err != nil || config.PlatformSKUs[0].BigID != "b" {
		t.Fatalf("config = %+v err = %v", config, err)
	}
	if id, err := config.PageID(PageStoreRoot); err != nil || id != "page-1" {
		t.Fatalf("store root id = %q err = %v", id, err)
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
	page, err := client.KnownPage(ctx, config, PageStoreRoot, PageRequest{Entitlements: []string{inventory.Entitlements[0].ID}, InventoryVersion: inventory.ETag})
	if err != nil || page.HeaderListsVersion != "u2" || page.Buttons[0].Ownership != "Owned" {
		t.Fatalf("page = %+v err = %v", page, err)
	}
	rows := page.Layout[0].Rows
	if top := rows[0].Component(ComponentTopBarSearch); top == nil || !top.Visible || len(top.Raw) == 0 {
		t.Fatalf("top bar = %+v", top)
	}
	if banner := rows[1].Component(ComponentPromoBanner); banner == nil || banner.MainText.Value != "Try it" ||
		banner.MainImage.URL == "" || banner.LinksTo.LinkType != "internal" {
		t.Fatalf("banner = %+v", banner)
	}
	curated := rows[2]
	list := curated.ItemList()
	if curated.Title() != "New" || list == nil || list.TotalItems != 9 || !list.RowConfig.SeeAllVisible || len(curated.Queries) != 0 {
		t.Fatalf("curated row = %+v", curated)
	}
	item := list.Items[0]
	if item.Title.Neutral() != "Alpha" || item.Description.Neutral() != "About" || item.Thumbnail.URL == "" ||
		item.Rating.TotalCount != 10 || item.Price.ListPrice != 990 || item.PackIdentity[0].UUID != "u" || string(item.Ownership) != `"NotOwned"` {
		t.Fatalf("item = %+v", item)
	}
	if seeAll, ok := list.LinksTo.PageID(); !ok || seeAll != "MultiItemPage_p|PagedList_x" {
		t.Fatalf("see all = %q ok = %v", seeAll, ok)
	}
	if nav := rows[3].Component(ComponentNavButtonList); nav == nil || nav.Buttons[0].Images[0].LocalPath == "" {
		t.Fatalf("nav = %+v", nav)
	}
	if len(rows[4].Queries) != 1 || rows[4].Queries[0].OrTags[0] != "new" || rows[4].ItemList().Items != nil || rows[4].Title() != "" {
		t.Fatalf("query row = %+v", rows[4])
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

// A page name the session config lacks fails locally, naming the known keys, and never reaches the
// service, which answers any unmapped id with 400.
func TestUnknownPageSendsNoRequest(t *testing.T) {
	var layoutRequests atomic.Int32
	client, _ := newStore(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v2.0/layout/pages/") {
			layoutRequests.Add(1)
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	config := &SessionConfig{KnownPages: map[string]string{PageStoreRoot: "store-id", PageSkinsRoot: "skins-id", PageWishlist: ""}}
	_, err := client.KnownPage(context.Background(), config, "home", PageRequest{})
	if !errors.Is(err, ErrUnknownPage) {
		t.Fatalf("err = %v, want ErrUnknownPage", err)
	}
	if msg := err.Error(); !strings.Contains(msg, `"home"`) || !strings.Contains(msg, "skinsRoot, storeRoot, wishlist") || strings.Contains(msg, "store-id") {
		t.Fatalf("error must name the missing key and the known keys only: %q", msg)
	}
	if _, err := config.PageID(PageWishlist); !errors.Is(err, ErrUnknownPage) {
		t.Fatalf("an empty page id resolved: %v", err)
	}
	if n := layoutRequests.Load(); n != 0 {
		t.Fatalf("sent %d layout requests for an unknown page", n)
	}
}

// A "See All" link's escaped page id reaches the service as the same id.
func TestLinkPageIDRoundTrips(t *testing.T) {
	var path string
	client, _ := newStore(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_, _ = io.WriteString(w, `{"result":{"pageId":"x","layout":[]}}`)
	})
	id, ok := (&Link{LinksTo: "MultiItemPage_p%7cPagedList_x", LinkType: "pageId"}).PageID()
	if !ok {
		t.Fatal("page link not resolved")
	}
	if _, err := client.Page(context.Background(), PageByID, id, PageRequest{}); err != nil || path != "/api/v2.0/layout/pages/MultiItemPage_p|PagedList_x" {
		t.Fatalf("path = %q err = %v", path, err)
	}
	if _, ok := (&Link{LinksTo: "Internal_Pass", LinkType: "internal"}).PageID(); ok {
		t.Fatal("an internal link resolved to a page id")
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

// Synthesized in the live service's search and detail page shapes, not captured payloads.
const (
	searchPageFixture = `{"result":{"pageId":"Search_SearchResults","layout":[{"sectionName":"rows","rows":[
{"controlId":"SearchBar","components":[{"type":"searchBarComp","search":"castle","sortBy":"relevance","sortDirection":"DESC","filters":{}}]},
{"controlId":"GridList","components":[{"type":"pagedItemListComp","totalItems":785,"continuationToken":"more",
 "items":[{"id":"9490fb47-4ba4-419f-bd3f-e0b8557a4304","title":"CASTLE","ownership":"NotOwned",
  "price":{"listPrice":660,"currencyId":"c","virtualCurrencyType":"Minecoin"}}]}]}]}]}}`
	detailPageFixture = `{"result":{"id":"9490fb47-4ba4-419f-bd3f-e0b8557a4304","pageId":"ItemDetail_9490fb47-4ba4-419f-bd3f-e0b8557a4304",
"layout":[{"sectionName":"rows","rows":[
{"controlId":"ItemSummary","components":[
 {"type":"itemSummaryComp","item":{"id":"9490fb47-4ba4-419f-bd3f-e0b8557a4304","title":"CASTLE","creatorName":"Novasoft",
  "tags":[{"name":"Roleplay","linksToInfo":{"linksTo":"Tag_subgenre.roleplay","linkType":"pageId"}}]}},
 {"type":"purchaseInfoComp","price":{"listPrice":660,"currencyId":"c","virtualCurrencyType":"Minecoin"}}]},
{"controlId":"ItemDescription","components":[{"type":"headerComp","headerText":"Description"},
 {"type":"itemDescriptionComp","description":"A castle.","playerCount":"1-22"}]},
{"controlId":"ImageGallery","components":[{"type":"imageGalleryComp","images":[{"type":"Unknown","url":"https://cdn.example.test/s0.jpg"}]}]},
{"controlId":"RatingRow","components":[{"type":"ratingComp","rating":{"average":4.0,"totalCount":102}}]}]}]}}`
)

// Search renders the session config's searchResults page with the game's search body.
func TestSearchPostsTheSearchResultsPage(t *testing.T) {
	var body map[string]any
	client, _ := newStore(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2.0/layout/pages/results-page" {
			t.Errorf("search reached %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = io.WriteString(w, searchPageFixture)
	})
	config := &SessionConfig{KnownPages: map[string]string{"searchResults": "results-page"}}
	page, err := client.Search(context.Background(), config, SearchRequest{Search: "castle"}, PageRequest{Entitlements: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"search": "castle", "sortBy": "Relevance", "sortDirection": "Desc", "filterPastRealmsPlus": false,
		"filterCurrentRealmsPlus": false, "filters": map[string]any{}, "entitlements": []any{}, "inventoryVersion": "", "listVersion": ""}
	for key, value := range want {
		got, _ := json.Marshal(body[key])
		if expected, _ := json.Marshal(value); string(got) != string(expected) {
			t.Errorf("body[%q] = %s, want %s", key, got, expected)
		}
	}
	results := page.Component(ComponentPagedItemList)
	if results == nil || results.ContinuationToken != "more" || results.TotalItems != 785 || results.Items[0].Title.Neutral() != "CASTLE" {
		t.Fatalf("results = %+v", results)
	}
}

// An offer's detail page decodes its summary, price, description, gallery and rating components.
func TestItemDetailDecodesComponents(t *testing.T) {
	client, _ := newStore(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2.0/layout/pages/productId/9490fb47-4ba4-419f-bd3f-e0b8557a4304" {
			t.Errorf("detail reached %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, detailPageFixture)
	})
	page, err := client.Page(context.Background(), PageByProductID, "9490fb47-4ba4-419f-bd3f-e0b8557a4304", PageRequest{Entitlements: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	summary, purchase := page.Component(ComponentItemSummary), page.Component(ComponentPurchaseInfo)
	description, gallery, rating := page.Component(ComponentItemDescription), page.Component(ComponentImageGallery), page.Component(ComponentRating)
	if summary == nil || summary.Item == nil || summary.Item.CreatorName != "Novasoft" || summary.Item.Tags[0].Name != "Roleplay" {
		t.Fatalf("summary = %+v", summary)
	}
	if purchase == nil || purchase.Price == nil || purchase.Price.ListPrice != 660 {
		t.Fatalf("purchase = %+v", purchase)
	}
	if description == nil || description.Description != "A castle." || gallery == nil || len(gallery.Images) != 1 ||
		rating == nil || rating.Rating == nil || rating.Rating.TotalCount != 102 {
		t.Fatalf("description = %+v gallery = %+v rating = %+v", description, gallery, rating)
	}
}

// An offer sells at its sale price during a sale, and its thumbnail is the Thumbnail-typed image.
func TestItemPriceAndThumbnail(t *testing.T) {
	var item Item
	if err := json.Unmarshal([]byte(`{"id":"a","price":{"listPrice":990,"saleInfo":{"salePrice":490}},
"thumbnail":{"type":"Thumbnail","url":"https://cdn.example.test/t.png"},"images":[{"type":"Screenshot","url":"https://cdn.example.test/s.png"}]}`), &item); err != nil {
		t.Fatal(err)
	}
	if item.Price.Amount() != 490 || item.ThumbnailURL() != "https://cdn.example.test/t.png" {
		t.Fatalf("amount = %d thumbnail = %q", item.Price.Amount(), item.ThumbnailURL())
	}
	if (&Price{ListPrice: 320}).Amount() != 320 || (&Item{Images: item.Images}).ThumbnailURL() != "" {
		t.Fatal("list price or missing thumbnail misread")
	}
}

// An offer on sale for free sells at zero; a sale without a price leaves the list price.
func TestItemSalePriceOfZeroIsFree(t *testing.T) {
	var free, unpriced Price
	if err := json.Unmarshal([]byte(`{"listPrice":990,"saleInfo":{"salePrice":0}}`), &free); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"listPrice":990,"saleInfo":{"discount":0.5}}`), &unpriced); err != nil {
		t.Fatal(err)
	}
	if free.Amount() != 0 || unpriced.Amount() != 990 {
		t.Fatalf("free = %d, unpriced = %d", free.Amount(), unpriced.Amount())
	}
}
