// Package mcservices checks Minecraft ownership through Minecraft services for an
// app registration Mojang has approved, signed in with a Microsoft OAuth token.
package mcservices

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/df-mc/go-xsapi/v2/xal"
	"github.com/df-mc/go-xsapi/v2/xal/xasu"
	"github.com/df-mc/go-xsapi/v2/xal/xsts"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

// OAuthConfig returns the device-code config for an approved app in the consumers tenant.
func OAuthConfig(clientID string) *oauth2.Config {
	endpoint := microsoft.AzureADEndpoint("consumers")
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	return &oauth2.Config{
		ClientID: clientID,
		Endpoint: endpoint,
		Scopes:   []string{"XboxLive.signin", "offline_access"},
	}
}

// Entitlements is the license answer for one account.
type Entitlements struct {
	Items     []Item
	RequestID string // Empty when produced by Parse.
	// Signed is the response's top-level JWT, kept for caching; nil for an unsigned empty
	// answer. Its signature is never verified: Mojang publishes no key for it.
	Signed    []byte
	IssuedAt  time.Time
	ExpiresAt time.Time // Zero when the JWT carries no exp claim.
}

// Item is one entitlement. Source is empty when produced by Parse.
type Item struct {
	Name, Source string
}

// minecraftItems are the entitlement names that grant Minecraft.
var minecraftItems = []string{"game_minecraft_bedrock", "product_minecraft_bedrock", "game_minecraft", "product_minecraft"}

// PlaysMinecraft reports whether any item grants Minecraft.
func (e *Entitlements) PlaysMinecraft() bool {
	return slices.ContainsFunc(e.Items, func(it Item) bool { return slices.Contains(minecraftItems, it.Name) })
}

var (
	// ErrAppNotApproved means Minecraft services rejected the app registration.
	ErrAppNotApproved = errors.New("mcservices: app registration not approved for Minecraft services")
	// ErrUnauthorized means a token was missing, expired or rejected.
	ErrUnauthorized = errors.New("mcservices: unauthorized")
	// ErrMalformedResponse means a 200 response could not be decoded.
	ErrMalformedResponse = errors.New("mcservices: malformed response")
	// ErrRequestIDMismatch means the license response echoed a different requestId.
	ErrRequestIDMismatch = errors.New("mcservices: requestId mismatch")
)

// Xbox XErr codes returned by XSTS.
const (
	XErrNoProfile            uint32 = 2148916233
	XErrRegionUnavailable    uint32 = 2148916235
	XErrAdultVerification    uint32 = 2148916236
	XErrAdultVerificationAlt uint32 = 2148916237
	XErrChildAccount         uint32 = 2148916238
)

// XboxError is an Xbox authentication refusal carrying its XErr code.
type XboxError struct {
	XErr uint32
}

func (e *XboxError) Error() string {
	return fmt.Sprintf("mcservices: xbox refused sign-in (XErr %d)", e.XErr)
}

// endpoints holds the service URLs so tests can point them at local servers.
type endpoints struct {
	userAuth, xsts, login, license string
}

var defaultEndpoints = endpoints{
	userAuth: "https://user.auth.xboxlive.com/user/authenticate",
	xsts:     "https://xsts.auth.xboxlive.com/xsts/authorize",
	login:    "https://api.minecraftservices.com/authentication/login_with_xbox",
	license:  "https://api.minecraftservices.com/entitlements/license",
}

// maxBody bounds each response read.
const maxBody = 4 << 20

// Fetch returns the account's entitlements; any error means ownership could not be checked.
func Fetch(ctx context.Context, client *http.Client, msToken *oauth2.Token) (*Entitlements, error) {
	return fetch(ctx, client, msToken, defaultEndpoints)
}

// fetch is Fetch against ep.
func fetch(ctx context.Context, client *http.Client, msToken *oauth2.Token, ep endpoints) (*Entitlements, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if !msToken.Valid() {
		return nil, ErrUnauthorized
	}

	var user xasu.Token
	if err := xboxPost(ctx, client, ep.userAuth, map[string]any{
		"Properties": map[string]any{
			"AuthMethod": "RPS",
			"SiteName":   "user.auth.xboxlive.com",
			"RpsTicket":  "d=" + msToken.AccessToken,
		},
		"RelyingParty": "http://auth.xboxlive.com",
		"TokenType":    "JWT",
	}, &user); err != nil {
		return nil, err
	}
	if !user.Valid() || len(user.DisplayClaims.UserInfo) == 0 {
		return nil, fmt.Errorf("%w: user token", ErrMalformedResponse)
	}

	var xstsToken xsts.Token
	if err := xboxPost(ctx, client, ep.xsts, map[string]any{
		"Properties": map[string]any{
			"SandboxId":  "RETAIL",
			"UserTokens": []string{user.Token},
		},
		"RelyingParty": "rp://api.minecraftservices.com/",
		"TokenType":    "JWT",
	}, &xstsToken); err != nil {
		return nil, err
	}
	if !xstsToken.Valid() {
		return nil, fmt.Errorf("%w: xsts token", ErrMalformedResponse)
	}

	var login struct {
		AccessToken string `json:"access_token"`
	}
	body, err := json.Marshal(map[string]string{"identityToken": xstsToken.String()})
	if err != nil {
		return nil, err
	}
	if err := serviceDo(ctx, client, http.MethodPost, ep.login, "", body, &login); err != nil {
		return nil, err
	}
	if login.AccessToken == "" {
		return nil, fmt.Errorf("%w: login", ErrMalformedResponse)
	}

	requestID := uuid.New()
	var license struct {
		Items []struct {
			Name   string `json:"name"`
			Source string `json:"source"`
		} `json:"items"`
		Signature string `json:"signature"`
		RequestID string `json:"requestId"`
	}
	licenseURL := ep.license + "?" + url.Values{"requestId": {requestID.String()}}.Encode()
	if err := serviceDo(ctx, client, http.MethodGet, licenseURL, login.AccessToken, nil, &license); err != nil {
		return nil, err
	}
	if echoed, err := uuid.Parse(license.RequestID); err != nil || echoed != requestID {
		return nil, ErrRequestIDMismatch
	}

	e := &Entitlements{RequestID: license.RequestID}
	for _, it := range license.Items {
		e.Items = append(e.Items, Item{Name: it.Name, Source: it.Source})
	}
	if license.Signature == "" {
		if len(e.Items) > 0 {
			return nil, fmt.Errorf("%w: unsigned items", ErrMalformedResponse)
		}
		return e, nil
	}
	signed, err := Parse([]byte(license.Signature))
	if err != nil {
		return nil, err
	}
	if !slices.Equal(names(e.Items), names(signed.Items)) {
		return nil, fmt.Errorf("%w: signed entitlements differ from items", ErrMalformedResponse)
	}
	e.Signed, e.IssuedAt, e.ExpiresAt = signed.Signed, signed.IssuedAt, signed.ExpiresAt
	return e, nil
}

// names returns the sorted distinct item names.
func names(items []Item) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.Name
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// signedClaims is the payload of the top-level entitlements JWT.
type signedClaims struct {
	jwt.Claims
	Entitlements *[]struct {
		Name string `json:"name"`
	} `json:"entitlements"`
}

// Parse decodes a cached Signed document without verifying its signature, which no
// published key can check; expiry is reported in ExpiresAt, not enforced.
func Parse(signed []byte) (*Entitlements, error) {
	tok, err := jwt.ParseSigned(string(signed), []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, fmt.Errorf("%w: signature: %v", ErrMalformedResponse, err)
	}
	var claims signedClaims
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, fmt.Errorf("%w: signature claims: %v", ErrMalformedResponse, err)
	}
	if claims.Entitlements == nil || claims.IssuedAt == nil {
		return nil, fmt.Errorf("%w: signature claims incomplete", ErrMalformedResponse)
	}
	e := &Entitlements{Signed: bytes.Clone(signed), IssuedAt: claims.IssuedAt.Time()}
	if claims.Expiry != nil {
		e.ExpiresAt = claims.Expiry.Time()
	}
	for _, it := range *claims.Entitlements {
		e.Items = append(e.Items, Item{Name: it.Name})
	}
	return e, nil
}

// xboxPost posts an Xbox authentication request, mapping XErr bodies to *XboxError.
func xboxPost(ctx context.Context, client *http.Client, endpoint string, reqBody, dst any) error {
	body, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-xbl-contract-version", "1")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var xerr struct {
			XErr uint32 `json:"XErr"`
		}
		if json.Unmarshal(data, &xerr) == nil && xerr.XErr != 0 {
			return &XboxError{XErr: xerr.XErr}
		}
		return statusError(resp)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("%w: %s", ErrMalformedResponse, endpoint)
	}
	return nil
}

// serviceDo calls a Minecraft services endpoint, with bearer auth when token is set.
func serviceDo(ctx context.Context, client *http.Client, method, endpoint, token string, body []byte, dst any) error {
	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reqBody)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusForbidden {
		var e struct {
			ErrorMessage string `json:"errorMessage"`
		}
		if json.Unmarshal(data, &e) == nil && strings.Contains(e.ErrorMessage, "Invalid app registration") {
			return ErrAppNotApproved
		}
	}
	if resp.StatusCode != http.StatusOK {
		return statusError(resp)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("%w: %s", ErrMalformedResponse, req.URL.Path)
	}
	return nil
}

// statusError maps 401 to ErrUnauthorized and any other status to *xal.StatusError.
func statusError(resp *http.Response) error {
	if resp.StatusCode == http.StatusUnauthorized {
		return ErrUnauthorized
	}
	return xal.UnexpectedStatus(resp)
}
