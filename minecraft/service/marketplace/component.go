package marketplace

import (
	"encoding/json"
	"net/url"
)

// Component types of store layout rows. The client presents a row by the types of its components;
// a row's control id only names the visual factory.
const (
	ComponentItemList        = "itemListComp"
	ComponentPagedItemList   = "pagedItemListComp"
	ComponentHeader          = "headerComp"
	ComponentCarousel        = "carouselComp"
	ComponentPromoBanner     = "promoBannerComp"
	ComponentNavButtonList   = "navButtonListComp"
	ComponentPlatformCoin    = "platformCoinOfferComp"
	ComponentTopBarMinecoin  = "topBarMinecoinComp"
	ComponentTopBarSearch    = "topBarSearchComp"
	ComponentTopBarInventory = "topBarInventoryComp"
	ComponentSearchBar       = "searchBarComp"
	ComponentItemSummary     = "itemSummaryComp"
	ComponentPurchaseInfo    = "purchaseInfoComp"
	ComponentItemDescription = "itemDescriptionComp"
	ComponentImageGallery    = "imageGalleryComp"
	ComponentRating          = "ratingComp"
)

// Component is one presentation component of a layout row. Members are filled per Type; Raw keeps
// the whole object for members not modelled here.
type Component struct {
	Type    string `json:"type"`
	LinksTo *Link  `json:"linksToInfo"` // where activating the component goes; an item list's "See All"

	// itemListComp and pagedItemListComp: the curated offers, of TotalItems in all (it may exceed
	// len(Items); LinksTo then names the page listing them all).
	TotalItems int        `json:"totalItems"`
	Items      []Item     `json:"items"`
	RowConfig  *RowConfig `json:"customStoreRowConfiguration"`
	// pagedItemListComp: the token [Client.ContinueRow] loads the next items with.
	ContinuationToken string `json:"continuationToken"`

	// itemSummaryComp: the offer a detail page presents.
	Item *Item `json:"item"`
	// purchaseInfoComp: the offer's price.
	Price *Price `json:"price"`
	// itemDescriptionComp.
	Description string `json:"description"`
	// imageGalleryComp: the offer's screenshots.
	Images []Image `json:"images"`
	// ratingComp.
	Rating *Rating `json:"rating"`

	// headerComp.
	HeaderText string `json:"headerText"`
	Text       *Text  `json:"text"`

	// promoBannerComp.
	FactoryID     string `json:"factoryId"`
	MainText      *Text  `json:"mainText"`
	MainImage     *Image `json:"mainImage"`
	FallbackImage *Image `json:"fallbackImage"`
	StartDate     string `json:"startDate"`
	EndDate       string `json:"endDate"`

	// navButtonListComp.
	Buttons []NavButton `json:"buttons"`

	// topBar*Comp.
	Visible        bool   `json:"isVisible"`
	Icon           *Image `json:"topBarIcon"`
	InventoryTitle *Text  `json:"inventoryTitle"`

	Raw json.RawMessage `json:"-"`
}

// UnmarshalJSON decodes the modelled members and keeps the object in Raw.
func (c *Component) UnmarshalJSON(b []byte) error {
	type plain Component
	if err := json.Unmarshal(b, (*plain)(c)); err != nil {
		return err
	}
	c.Raw = append(json.RawMessage(nil), b...)
	return nil
}

// Link is a navigation target.
type Link struct {
	LinksTo         string `json:"linksTo"`
	LinkType        string `json:"linkType"`    // "pageId" names a layout page; others, such as "internal", name client screens
	DisplayType     string `json:"displayType"` // the JSON-UI screen that presents the target
	ScreenTitle     *Text  `json:"screenTitle"`
	NavigateInPlace bool   `json:"navigateInPlace"`
}

// PageID returns the layout page id a "pageId" link names, ready for [Client.Page]. The service
// sends the id path-escaped ("%7c" for '|'); it is unescaped here and escaped again on request.
func (l *Link) PageID() (string, bool) {
	if l == nil || l.LinkType != "pageId" || l.LinksTo == "" {
		return "", false
	}
	id, err := url.PathUnescape(l.LinksTo)
	if err != nil || id == "" {
		return "", false
	}
	return id, true
}

// Text is a display text: a literal or a localization key, with its style kept undecoded.
type Text struct {
	Value        string          `json:"value"`
	Replacements json.RawMessage `json:"replacements"`
	Style        json.RawMessage `json:"style"`
}

// RowConfig overrides how an item list row presents its offers.
type RowConfig struct {
	SeeAllVisible       bool `json:"seeAllVisible"`
	ArrowsVisible       bool `json:"arrowsVisible"`
	MaxOffers           int  `json:"maxOffers"`
	VisibleOffersPerRow int  `json:"visibleOffersPerRow"` // 0 leaves it to the screen
}

// NavButton is one button of a navigation button row.
type NavButton struct {
	Name          string          `json:"navButtonName"`
	Image         string          `json:"image"` // resource-pack texture path
	Images        []Image         `json:"images"`
	LinksTo       *Link           `json:"linksToInfo"`
	SizeIsFill    bool            `json:"buttonSizeIsFill"`
	DefaultColor  json.RawMessage `json:"defaultColor"`
	InteractColor json.RawMessage `json:"interactColor"`
}
