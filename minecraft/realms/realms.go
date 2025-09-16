package realms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/auth"
	"golang.org/x/oauth2"
)

// Client is an instance of the realms api with a token.
type Client struct {
	getTokenSrc func() oauth2.TokenSource
	getAuthCl   func() *auth.AuthClient

	xblToken *auth.XBLToken
}

type realmService interface {
	RealmAddress(ctx context.Context, realmID int) (string, error)
	OnlinePlayers(ctx context.Context, realmID int) ([]Player, error)
}

const realmsBaseURL = "https://pocket.realms.minecraft.net"

// NewClient returns a new Client instance with the supplied token source for authentication.
// If httpClient is nil, http.DefaultClient will be used to request the realms api.
func NewClient(getTS func() oauth2.TokenSource, getAC func() *auth.AuthClient) *Client {
	if getAC == nil {
		getAC = func() *auth.AuthClient { return auth.DefaultClient }
	}
	return &Client{
		getTokenSrc: getTS,
		getAuthCl:   getAC,
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

	svc realmService `json:"-"`
}

func (r *Realm) Address(ctx context.Context) (address string, err error) {
	return r.svc.RealmAddress(ctx, r.ID)
}

func (r *Realm) OnlinePlayers(ctx context.Context) (players []Player, err error) {
	return r.svc.OnlinePlayers(ctx, r.ID)
}

// RealmAddress returns the address and port to connect to a realm from the api,
// will wait for the realm to start if it is currently offline.
func (c *Client) RealmAddress(ctx context.Context, realmID int) (address string, err error) {
	ticker := time.NewTicker(time.Second * 3)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
			body, status, err := c.requestGet(ctx, fmt.Sprintf("/worlds/%d/join", realmID))
			if err != nil {
				switch status {
				case 503:
					continue
				case 404:
					return "", fmt.Errorf("realm not found")
				}
				return "", err
			}

			var data struct {
				Address       string `json:"address"`
				PendingUpdate bool   `json:"pendingUpdate"`
			}
			if err := json.Unmarshal(body, &data); err != nil {
				return "", err
			}

			ap, err := netip.ParseAddrPort(data.Address)
			if err != nil || !ap.Addr().Is4() || ap.Port() == 0 {
				// TODO: remove this or just return err instead of slog
				slog.ErrorContext(ctx, "invalid realm address", "addr", data.Address, "err", err, "response_body", string(body))
			}

			return data.Address, nil
		}
	}
}

// OnlinePlayers returns all the online players of a realm.
// Returns a 403 error if the current user is not the owner of the Realm.
func (c *Client) OnlinePlayers(ctx context.Context, realmID int) (players []Player, err error) {
	body, _, err := c.requestGet(ctx, fmt.Sprintf("/worlds/%d", realmID))
	if err != nil {
		return nil, err
	}

	var response Realm
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	return response.Players, nil
}

// RealmByInviteCode gets a realm by its invite code.
func (c *Client) RealmByInviteCode(ctx context.Context, code string) (Realm, error) {
	body, _, err := c.requestGet(ctx, fmt.Sprintf("/worlds/v1/link/%s", code))
	if err != nil {
		return Realm{}, err
	}

	var r Realm
	if err := json.Unmarshal(body, &r); err != nil {
		return Realm{}, err
	}
	r.svc = c

	return r, nil
}

// AcceptRealmInviteCode accepts a realm invite code and returns the realm object if successful.
func (c *Client) AcceptRealmInviteCode(ctx context.Context, inviteCode string) (Realm, error) {
	body, statusCode, err := c.requestPost(ctx, fmt.Sprintf("/invites/v1/link/accept/%s", inviteCode))
	if err != nil {
		return Realm{}, err
	}
	if statusCode != 200 {
		return Realm{}, fmt.Errorf("failed with status code: %d", statusCode)
	}

	var r Realm
	if err := json.Unmarshal(body, &r); err != nil {
		return Realm{}, err
	}
	r.svc = c
	return r, nil
}

// Realms gets a list of all realms the token has access to.
func (c *Client) Realms(ctx context.Context) ([]Realm, error) {
	body, _, err := c.requestGet(ctx, "/worlds")
	if err != nil {
		return nil, err
	}

	var resp struct {
		Servers []Realm `json:"servers"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	for i := range resp.Servers {
		resp.Servers[i].svc = c
	}

	return resp.Servers, nil
}

// xboxToken returns the xbox token used for the api.
func (c *Client) xboxToken(ctx context.Context, forceRefresh bool) (*auth.XBLToken, error) {
	if !forceRefresh && c.xblToken != nil && !c.xblToken.AuthorizationToken.Expired() {
		return c.xblToken, nil
	}

	tokenSrc := c.getTokenSrc()
	if tokenSrc == nil {
		return nil, fmt.Errorf("token source is nil")
	}

	authClient := c.getAuthCl()
	if authClient == nil {
		return nil, fmt.Errorf("auth client is nil")
	}

	t, err := tokenSrc.Token()
	if err != nil {
		return nil, err
	}

	c.xblToken, err = authClient.RequestXBLToken(ctx, t, realmsBaseURL + "/")
	return c.xblToken, err
}

func (c *Client) requestGet(ctx context.Context, path string) (body []byte, status int, err error) {
	return c.request(ctx, "GET", path, nil)
}

// request sends an http get request to path with the right headers for the api set.
func (c *Client) requestPost(ctx context.Context, path string) (body []byte, status int, err error) {
	return c.request(ctx, "POST", path, nil)
}

func (c *Client) request(ctx context.Context, method string, path string, body []byte) (responseBody []byte, status int, err error) {
	if string(path[0]) != "/" {
		path = "/" + path
	}

	authClient := c.getAuthCl()
	if authClient == nil {
		return nil, 0, fmt.Errorf("auth client is nil")
	}

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, realmsBaseURL+path, reqBody)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "MCPE/UWP")
	req.Header.Set("Client-Version", "1.10.1")
	xbl, err := c.xboxToken(ctx, false)
	if err != nil {
		return nil, 0, err
	}
	xbl.SetAuthHeader(req)

	resp, err := authClient.Do(ctx, req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	responseBody, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	if resp.StatusCode >= 400 {
		return responseBody, resp.StatusCode, fmt.Errorf("HTTP Error: %d", resp.StatusCode)
	}

	return responseBody, resp.StatusCode, nil
}
