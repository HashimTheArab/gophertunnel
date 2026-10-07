// Package layout reads the layout service, which composes OreUI screens such as the Servers tab
// from fabs of experiences.
package layout

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/service"
	"github.com/sandertv/gophertunnel/minecraft/service/internal"
	"github.com/sandertv/gophertunnel/minecraft/service/internal/request"
)

// ServerTab is the layout of the Servers tab when no flight names another.
const ServerTab = "ServerTab"

// Fab types.
const (
	FabExperience     = "ExperienceFab"
	FabExperienceList = "ExperienceListFab"
	FabExperiencePage = "ExperiencePdpFab"
)

// Environment is the discovered layout service endpoint.
type Environment struct {
	internal.ServiceEnvironment
	// HTTPClient sends the requests; nil uses http.DefaultClient.
	HTTPClient *http.Client `json:"-"`
}

// ServiceName implements [service.Environment] and returns "layout".
func (*Environment) ServiceName() string { return "layout" }

// New returns a Client authorized by src.
func (e *Environment) New(src service.TokenSource) *Client {
	return &Client{env: e, src: src}
}

// Client reads layouts; it is safe for concurrent use.
type Client struct {
	env *Environment
	src service.TokenSource
}

// Layout loads the layout with the given unescaped id, such as [ServerTab] or [Link.LayoutID].
func (c *Client) Layout(ctx context.Context, id string) (*Layout, error) {
	if id == "" || strings.ContainsAny(id, "/?#") {
		return nil, errors.New("service/layout: invalid layout id")
	}
	var result struct {
		Structure *Layout `json:"layoutStructure"`
	}
	target := c.env.ServiceURI.JoinPath("/api/v1.0/layout", url.PathEscape(id))
	if _, err := request.Do(ctx, c.env.HTTPClient, c.src, http.MethodPost, target, struct{}{}, &result, request.Options{}); err != nil {
		return nil, err
	}
	if result.Structure == nil {
		return nil, errors.New("service/layout: response has no layout structure")
	}
	return result.Structure, nil
}

// Layout is a screen composed of fabs.
type Layout struct {
	Title         Text          `json:"title"`
	RefreshPolicy RefreshPolicy `json:"refreshPolicy"`
	Body          struct {
		Fabs []Fab `json:"fabs"`
	} `json:"body"`
}

// Experiences returns every experience the layout's fabs present, each once, in fab order.
func (l *Layout) Experiences() []Experience {
	seen := make(map[uuid.UUID]bool)
	var experiences []Experience
	add := func(experience Experience) {
		if experience.ID != uuid.Nil && !seen[experience.ID] {
			seen[experience.ID] = true
			experiences = append(experiences, experience)
		}
	}
	for _, fab := range l.Body.Fabs {
		if fab.Experience != nil {
			add(*fab.Experience)
		}
		if fab.PagedExperiences != nil {
			for _, experience := range fab.PagedExperiences.Experiences {
				add(experience)
			}
		}
	}
	return experiences
}

// RefreshPolicy says how long a layout or fab may be shown before it is loaded again.
type RefreshPolicy struct {
	TimeToLiveSeconds      int `json:"timeToLiveInSeconds"`
	MinRefreshDelaySeconds int `json:"minRefreshDelayInSeconds"`
}

// TimeToLive returns the policy's time to live.
func (p RefreshPolicy) TimeToLive() time.Duration {
	return time.Duration(p.TimeToLiveSeconds) * time.Second
}

// ExperiencePage returns the experience page the layout's first [FabExperiencePage] presents, or
// nil. An experience's [Link] names a layout holding one.
func (l *Layout) ExperiencePage() *ExperiencePage {
	for _, fab := range l.Body.Fabs {
		if fab.ExperiencePage != nil {
			return fab.ExperiencePage
		}
	}
	return nil
}

// ExperiencePage is an experience's detail page.
type ExperiencePage struct {
	Title       Text       `json:"title"`
	Description Text       `json:"description"`
	Banner      Image      `json:"banner"`
	Activities  []Activity `json:"activities"`
	News        *struct {
		Title       Text `json:"title"`
		Description Text `json:"description"`
	} `json:"news"`
}

// Fab is one block of a layout. Type selects its members: an [FabExperience] presents Experience,
// an [FabExperienceList] lists PagedExperiences, an [FabExperiencePage] holds ExperiencePage.
// Variant names its presentation, such as "feature-play", "row", "hero" or "grid".
type Fab struct {
	ID               string        `json:"id"`
	Type             string        `json:"$type"`
	Variant          string        `json:"variant"`
	Title            Text          `json:"title"`
	RefreshPolicy    RefreshPolicy `json:"refreshPolicy"`
	Experience       *Experience   `json:"experience"`
	PagedExperiences *struct {
		Experiences []Experience `json:"experiences"`
	} `json:"pagedExperiences"`
	ExperiencePage *ExperiencePage `json:"experiencePdp"`

	Raw json.RawMessage `json:"-"` // the whole fab, for types not modelled here
}

// UnmarshalJSON decodes the modelled members and keeps the fab in Raw.
func (f *Fab) UnmarshalJSON(b []byte) error {
	type plain Fab
	if err := json.Unmarshal(b, (*plain)(f)); err != nil {
		return err
	}
	f.Raw = append(json.RawMessage(nil), b...)
	return nil
}

// Experience is a server experience, joined through the gatherings service by ID. Lists carry its
// listing only; a featured fab adds the description, artwork and activities.
type Experience struct {
	ID              uuid.UUID  `json:"experienceId"`
	Mode            string     `json:"mode"`
	Title           Text       `json:"title"`
	CreatorName     string     `json:"creatorName"`
	CreatorID       string     `json:"creatorId"`
	LinksTo         Link       `json:"linksTo"`
	Listing         Listing    `json:"listing"`
	Description     Text       `json:"description"`
	BackgroundImage Image      `json:"backgroundImage"`
	LogoImage       Image      `json:"logoImage"`
	Activities      []Activity `json:"activities"`
}

// Listing is what an experience shows in a list.
type Listing struct {
	DisplayImage Image `json:"displayImage"`
	MOTD         Text  `json:"motd"`
}

// Activity is one thing to do in an experience.
type Activity struct {
	Title       Text  `json:"title"`
	Subtitle    Text  `json:"subtitle"`
	Description Text  `json:"description"`
	Image       Image `json:"image"`
}

// Link names another layout (Type "layout") with an experience's details.
type Link struct {
	ID   string `json:"id"` // path-escaped
	Type string `json:"type"`
}

// LayoutID returns the unescaped id of the layout the link names, ready for [Client.Layout].
func (l Link) LayoutID() (string, bool) {
	if l.Type != "layout" || l.ID == "" {
		return "", false
	}
	id, err := url.PathUnescape(l.ID)
	return id, err == nil && id != ""
}

// Text is a display string.
type Text struct {
	Value string `json:"value"`
}

// Image is one artwork at up to three sizes.
type Image struct {
	Full    *ImageURL `json:"full"`
	Half    *ImageURL `json:"half"`
	Quarter *ImageURL `json:"quarter"`
}

// ImageURL is the address of one image size.
type ImageURL struct {
	URL string `json:"url"`
}

// URL returns the largest size's address, or "".
func (i Image) URL() string {
	for _, size := range []*ImageURL{i.Full, i.Half, i.Quarter} {
		if size != nil && size.URL != "" {
			return size.URL
		}
	}
	return ""
}
