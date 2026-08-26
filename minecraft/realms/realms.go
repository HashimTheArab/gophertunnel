package realms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/sandertv/gophertunnel/minecraft/auth/authclient"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"golang.org/x/oauth2"
)

// Client is an instance of the realms api with a token.
type Client struct {
	tokenSrc       oauth2.TokenSource
	xblToken       *auth.XBLToken
	httpClient     *http.Client
	authHTTPClient *http.Client
	requestFunc    func(ctx context.Context, method, path string, body []byte) ([]byte, int, error)

	negotiateMu sync.Mutex // Serialises Client-Version negotiation so one rejection triggers one search.

	versionMu        sync.Mutex
	preferredVersion string    // Version to send, empty for protocol.CurrentVersion.
	acceptedVersion  string    // Version Realms accepted, empty until a rejection forces a search.
	searchFailedAt   time.Time // When the last search found no accepted version.
}

const realmsRelyingParty = "https://pocket.realms.minecraft.net/"

const (
	statusRetryWith        = 277
	defaultRealmRetryAfter = 5 * time.Second
)

// realmsBaseURL is a variable so tests may point the client at a stub server.
var realmsBaseURL = "https://bedrock.frontendlegacy.realms.minecraft-services.net"

var (
	ErrPlayerNotInRealm = errors.New("player not in realm")
	ErrRealmNotFound    = errors.New("realm not found")
)

// NewClient returns a new Client instance with the supplied token source for authentication.
// If httpClient is nil, http.DefaultClient will be used to request the realms api.
// Xbox auth requests keep using the auth package's default client unless a
// caller explicitly supplies a client here or in ctx.
func NewClient(src oauth2.TokenSource, httpClient *http.Client) *Client {
	authHTTPClient := httpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{
		tokenSrc:       src,
		httpClient:     httpClient,
		authHTTPClient: authHTTPClient,
	}
}

// Player is a player in a Realm.
type Player struct {
	UUID       string `json:"uuid"`
	Name       string `json:"Name"`
	Operator   bool   `json:"operator"`
	Accepted   bool   `json:"accepted"`
	Online     bool   `json:"online"`
	Permission string `json:"permission"`
}

// Realm is the realm structure returned from the api.
type Realm struct {
	// ID is the unique id for this realm.
	ID int `json:"id"`
	// RemoteSubscriptionID is The subscription ID of the realm.
	RemoteSubscriptionID string `json:"remoteSubscriptionID"`
	// Owner is always an empty string.
	Owner string `json:"owner"`
	// OwnerUUID is the XboxUserID (XUID) of the owner.
	OwnerUUID string `json:"ownerUUID"`
	// Name is the name of the Realm.
	Name string `json:"name"`
	// MOTD is always an empty string.
	MOTD string `json:"motd"`
	// DefaultPermission is the default permission level of the Realm world.
	// one of ["MEMBER", "OPERATOR"]
	DefaultPermission string `json:"defaultPermission"`
	// State is the current state of the realm
	// one of: ["OPEN", "CLOSED"]
	State string `json:"state"`
	// DaysLeft is the days remaining before renewal of the Realm as an integer.
	// (always 0 for Realms where the current user is not the owner)
	DaysLeft int `json:"daysLeft"`
	// Expired is whether the Realm has expired as a trial or not.
	Expired bool `json:"expired"`
	// ExpiredTrial is whether the Realm has expired as a trial or not.
	ExpiredTrial bool `json:"expiredTrial"`
	// GracePeriod is whether the Realm is in its grace period after expiry or not.
	GracePeriod bool `json:"gracePeriod"`
	// WorldType is the world type of the currently loaded world.
	WorldType string `json:"worldType"`
	// Players is a list of the players currently online in the realm
	// NOTE: this is only sent when directly requesting a realm.
	Players []Player `json:"players"`
	// MaxPlayers is how many player slots this realm has.
	MaxPlayers int `json:"maxPlayers"`
	// MinigameName is always null
	MinigameName string `json:"minigameName"`
	// MinigameID is always null
	MinigameID string `json:"minigameId"`
	// MinigameImage is always null
	MinigameImage string `json:"minigameImage"`
	// ActiveSlot is unused, always 1
	ActiveSlot int `json:"activeSlot"`
	// Slots is unused, always null
	Slots []struct{} `json:"slots"`
	// Member is Unknown, always false. (even when member or owner)
	Member bool `json:"member"`
	// ClubID is the ID of the associated Xbox Live club as an integer.
	ClubID int64 `json:"clubId"`
	// SubscriptionRefreshStatus is Unknown, always null.
	SubscriptionRefreshStatus struct{} `json:"subscriptionRefreshStatus"`

	// client is the instance of Client that this belongs to.
	client *Client
}

// StoryOptIn is an opt-in state used by Realms Stories settings.
type StoryOptIn string

const (
	StoryOptInNone   StoryOptIn = "NONE"
	StoryOptInOptIn  StoryOptIn = "OPT_IN"
	StoryOptInOptOut StoryOptIn = "OPT_OUT"
)

// StorySettings contains the settings controlling Realms Stories for a realm.
type StorySettings struct {
	AutoStories   bool       `json:"autostories"`
	Coordinates   bool       `json:"coordinates"`
	Notifications bool       `json:"notifications"`
	PlayerOptIn   StoryOptIn `json:"playerOptIn"`
	RealmOptIn    StoryOptIn `json:"realmOptIn"`
	Timeline      bool       `json:"timeline"`
}

// RealmAddress contains the address returned by the Realms join endpoint along
// with the signalling protocol used for connecting to it.
type RealmAddress struct {
	Address           string          `json:"address"`
	NetworkProtocol   NetworkProtocol `json:"networkProtocol"`
	PendingUpdate     bool            `json:"pendingUpdate"`
	SessionRegionData struct {
		RegionName     string `json:"regionName"`
		ServiceQuality int    `json:"serviceQuality"`
	} `json:"sessionRegionData"`
}

// Address requests the address and protocol used to connect to this realm.
// It will wait for the realm to start if it is currently offline.
func (r *Realm) Address(ctx context.Context, pingResults ...PingResult) (RealmAddress, error) {
	if r.client == nil {
		return RealmAddress{}, fmt.Errorf("realm client is nil")
	}
	return r.client.RealmAddress(ctx, r.ID, pingResults...)
}

// RealmAddress requests the address and protocol used to connect to a realm
// from the api, and waits for the realm to start if it is currently offline.
func (r *Client) RealmAddress(ctx context.Context, realmID int, pingResults ...PingResult) (RealmAddress, error) {
	if pingResults == nil {
		pingResults = []PingResult{}
	}
	requestBody, err := json.Marshal(struct {
		JoinIntention string       `json:"joinIntention"`
		PingRegions   []PingResult `json:"pingRegions"`
	}{
		JoinIntention: "VANILLA",
		PingRegions:   pingResults,
	})
	if err != nil {
		return RealmAddress{}, fmt.Errorf("encode join request: %w", err)
	}
	for {
		body, status, err := r.requestPost(ctx, fmt.Sprintf("/worlds/%d/join", realmID), requestBody)
		if err != nil {
			switch status {
			case http.StatusServiceUnavailable, statusRetryWith:
				var retry *retryAfterError
				if !errors.As(err, &retry) {
					return RealmAddress{}, err
				}
				timer := time.NewTimer(retry.delay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return RealmAddress{}, ctx.Err()
				case <-timer.C:
					continue
				}
			case 404:
				return RealmAddress{}, ErrRealmNotFound
			case 403:
				return RealmAddress{}, ErrPlayerNotInRealm
			}
			return RealmAddress{}, err
		}

		var address RealmAddress
		if err := json.Unmarshal(body, &address); err != nil {
			return RealmAddress{}, err
		}
		return address, nil
	}
}

// OnlinePlayers gets all the players currently on this realm,
// Returns a 403 error if the current user is not the owner of the Realm.
func (r *Realm) OnlinePlayers(ctx context.Context) (players []Player, err error) {
	body, status, err := r.client.requestGet(ctx, fmt.Sprintf("/worlds/%d", r.ID))
	if err != nil {
		switch status {
		case 403:
			return nil, ErrPlayerNotInRealm
		case 404:
			return nil, ErrRealmNotFound
		}
		return nil, err
	}

	var response Realm
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	return response.Players, nil
}

// StorySettings gets the Realms Stories settings for this realm.
func (r *Realm) StorySettings(ctx context.Context) (StorySettings, error) {
	if r.client == nil {
		return StorySettings{}, fmt.Errorf("realm client is nil")
	}
	return r.client.StorySettings(ctx, r.ID)
}

// UpdateStorySettings updates the Realms Stories settings for this realm.
func (r *Realm) UpdateStorySettings(ctx context.Context, settings StorySettings) error {
	if r.client == nil {
		return fmt.Errorf("realm client is nil")
	}
	return r.client.UpdateStorySettings(ctx, r.ID, settings)
}

// OptInToStoryTimeline opts the authenticated player into this realm's Stories timeline
// without changing any other Stories settings.
func (r *Realm) OptInToStoryTimeline(ctx context.Context) error {
	if r.client == nil {
		return fmt.Errorf("realm client is nil")
	}
	return r.client.OptInToStoryTimeline(ctx, r.ID)
}

// StorySettings gets the Realms Stories settings for a realm.
func (r *Client) StorySettings(ctx context.Context, realmID int) (StorySettings, error) {
	body, _, err := r.requestGet(ctx, fmt.Sprintf("/worlds/%d/stories/settings", realmID))
	if err != nil {
		return StorySettings{}, err
	}
	var settings StorySettings
	if err := json.Unmarshal(body, &settings); err != nil {
		return StorySettings{}, err
	}
	return settings, nil
}

// UpdateStorySettings updates the Realms Stories settings for a realm.
func (r *Client) UpdateStorySettings(ctx context.Context, realmID int, settings StorySettings) error {
	body, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	_, _, err = r.requestPost(ctx, fmt.Sprintf("/worlds/%d/stories/settings", realmID), body)
	return err
}

// OptInToStoryTimeline opts the authenticated player into a realm's Stories timeline
// without changing any other Stories settings.
func (r *Client) OptInToStoryTimeline(ctx context.Context, realmID int) error {
	settings, err := r.StorySettings(ctx, realmID)
	if err != nil {
		return err
	}
	if settings.PlayerOptIn == StoryOptInOptIn {
		return nil
	}
	settings.PlayerOptIn = StoryOptInOptIn
	return r.UpdateStorySettings(ctx, realmID, settings)
}

// xboxToken returns the xbox token used for the api.
func (r *Client) xboxToken(ctx context.Context) (*auth.XBLToken, error) {
	if r.xblToken != nil && r.xblToken.Valid() {
		return r.xblToken, nil
	}
	if r.tokenSrc == nil {
		return nil, fmt.Errorf("token source is nil")
	}
	ctx = auth.WithContextClient(ctx, r.authHTTPClient)

	t, err := r.tokenSrc.Token()
	if err != nil {
		return nil, err
	}

	r.xblToken, err = auth.RequestXBLToken(ctx, t, realmsRelyingParty)
	return r.xblToken, err
}

func (r *Client) requestGet(ctx context.Context, path string) (body []byte, status int, err error) {
	return r.request(ctx, http.MethodGet, path, nil)
}

func (r *Client) requestPost(ctx context.Context, path string, requestBody []byte) (body []byte, status int, err error) {
	return r.request(ctx, http.MethodPost, path, requestBody)
}

func (r *Client) request(ctx context.Context, method, path string, requestBody []byte) (body []byte, status int, err error) {
	if r.requestFunc != nil {
		return r.requestFunc(ctx, method, path, requestBody)
	}
	sent := r.clientVersion()
	body, status, err = r.send(ctx, method, path, requestBody, sent)
	if !unknownClientVersion(status, body) {
		return body, status, err
	}
	version, retry := r.negotiateClientVersion(ctx, sent)
	if !retry {
		return body, status, err
	}
	return r.send(ctx, method, path, requestBody, version)
}

// send performs a single request against the realms api with an explicit
// Client-Version, without negotiating a replacement for a rejected one.
func (r *Client) send(ctx context.Context, method, path string, requestBody []byte, clientVersion string) (body []byte, status int, err error) {
	if path == "" {
		return nil, 0, fmt.Errorf("path is empty")
	}
	if path[0] != '/' {
		path = "/" + path
	}
	req, err := http.NewRequestWithContext(ctx, method, realmsBaseURL+path, bytes.NewReader(requestBody))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "libhttpclient/1.0.0.0")
	req.Header.Set("Client-Version", clientVersion)
	req.Header.Set("X-ClientPlatform", "Android")
	req.Header.Set("X-NetworkProtocolVersion", strconv.Itoa(protocol.CurrentProtocol))
	if requestBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	xbl, err := r.xboxToken(ctx)
	if err != nil {
		return nil, 0, err
	}
	xbl.SetAuthHeader(req)

	retryOptions := authclient.RetryOptions{}
	if method == http.MethodPost && strings.HasPrefix(path, "/worlds/") && strings.HasSuffix(path, "/join") {
		// Realm startup retries follow the service's Retry-After response rather than the generic HTTP backoff.
		retryOptions.Attempts = 1
	}
	resp, err := authclient.SendRequestWithRetries(ctx, r.httpClient, req, retryOptions)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	if resp.StatusCode == statusRetryWith || resp.StatusCode >= 400 {
		responseErr := httpResponseError(resp.StatusCode, body)
		if resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == statusRetryWith {
			if delay, ok := retryAfter(resp.Header.Get("Retry-After")); ok {
				return body, resp.StatusCode, &retryAfterError{delay: delay, err: responseErr}
			}
		}
		return body, resp.StatusCode, responseErr
	}

	return body, resp.StatusCode, nil
}

// retryAfterError carries the delay requested by a retryable Realms response.
type retryAfterError struct {
	delay time.Duration
	err   error
}

// Error returns the underlying Realms response error.
func (e *retryAfterError) Error() string {
	return e.err.Error()
}

// Unwrap returns the underlying Realms response error.
func (e *retryAfterError) Unwrap() error {
	return e.err
}

// retryAfter parses the integer seconds used by the vanilla Realms client. It reports false for a missing value and
// falls back to five seconds for a present value that cannot be parsed.
func retryAfter(value string) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	seconds, err := strconv.ParseUint(value, 10, 64)
	if err != nil || seconds > uint64((1<<63-1)/int64(time.Second)) {
		return defaultRealmRetryAfter, true
	}
	return time.Duration(seconds) * time.Second, true
}

const maxHTTPErrorBodyPreview = 512

// httpResponseError builds an error for an HTTP status >= 400, including a trimmed, truncated body preview when present.
func httpResponseError(statusCode int, body []byte) error {
	preview := body
	truncated := len(preview) > maxHTTPErrorBodyPreview
	if truncated {
		preview = preview[:maxHTTPErrorBodyPreview]
	}
	snippet := strings.TrimSpace(string(preview))
	if truncated {
		snippet += "..."
	}
	if snippet != "" {
		return fmt.Errorf("HTTP Error: %d: %s", statusCode, snippet)
	}
	return fmt.Errorf("HTTP Error: %d", statusCode)
}

// Realm gets a realm by its invite code.
func (c *Client) Realm(ctx context.Context, code string) (Realm, error) {
	body, _, err := c.requestGet(ctx, fmt.Sprintf("/worlds/v1/link/%s", code))
	if err != nil {
		return Realm{}, err
	}

	var realm Realm
	if err := json.Unmarshal(body, &realm); err != nil {
		return Realm{}, err
	}
	realm.client = c

	return realm, nil
}

// AcceptRealmInviteCode accepts a Realm invite code and returns the joined Realm.
func (c *Client) AcceptRealmInviteCode(ctx context.Context, code string) (Realm, error) {
	body, _, err := c.requestPost(ctx, fmt.Sprintf("/invites/v1/link/accept/%s", code), nil)
	if err != nil {
		return Realm{}, err
	}

	var realm Realm
	if err := json.Unmarshal(body, &realm); err != nil {
		return Realm{}, err
	}
	realm.client = c
	return realm, nil
}

// Realms gets a list of all realms the token has access to.
func (c *Client) Realms(ctx context.Context) ([]Realm, error) {
	body, _, err := c.requestGet(ctx, "/worlds")
	if err != nil {
		return nil, err
	}

	var response struct {
		Servers []Realm `json:"servers"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	realms := response.Servers
	for i := range realms {
		realms[i].client = c
	}

	return realms, nil
}
