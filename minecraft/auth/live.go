package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/auth/authclient"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

// TokenSource holds an oauth2.TokenSource which uses device auth to get a code. The user authenticates using
// a code. TokenSource prints the authentication code and URL to os.Stdout and uses DeviceAndroid.
// TokenSource automatically refreshes tokens.
var TokenSource oauth2.TokenSource = &tokenSource{a: authclient.DefaultClient, w: os.Stdout, d: DeviceAndroid}

// TokenSourceOption is a functional option for configuring token sources.
type TokenSourceOption func(*tokenSourceConfig)

type tokenSourceConfig struct {
	authClient *authclient.AuthClient
	writer     io.Writer
	device     Device
	token      *oauth2.Token
}

// WithWriter configures the token source to write authentication prompts to the specified writer.
func WithWriter(w io.Writer) TokenSourceOption {
	return func(c *tokenSourceConfig) {
		c.writer = w
	}
}

// WithDevice configures the token source to use the specified device type for authentication.
func WithDevice(d Device) TokenSourceOption {
	return func(c *tokenSourceConfig) {
		c.device = d
	}
}

// WithToken configures the token source to use an existing token for refresh.
func WithToken(t *oauth2.Token) TokenSourceOption {
	return func(c *tokenSourceConfig) {
		c.token = t
	}
}

// WithAuthClient configures the token source to use the specified auth client.
func WithAuthClient(ac *authclient.AuthClient) TokenSourceOption {
	return func(c *tokenSourceConfig) {
		c.authClient = ac
	}
}

func newTokenSourceConfig(opts ...TokenSourceOption) *tokenSourceConfig {
	config := &tokenSourceConfig{
		authClient: authclient.DefaultClient,
		writer:     os.Stdout,
		device:     DeviceAndroid,
	}
	for _, opt := range opts {
		opt(config)
	}
	return config
}

// NewTokenSource creates a new oauth2.TokenSource with the given options.
// If no token is provided, it will use device auth to get a new token.
// If a token is provided, it will refresh that token when expired.
// Default writer is os.Stdout, default device is DeviceAndroid.
func NewTokenSource(opts ...TokenSourceOption) oauth2.TokenSource {
	config := newTokenSourceConfig(opts...)

	ts := &tokenSource{
		a: config.authClient,
		w: config.writer,
		d: config.device,
		t: config.token,
	}

	if config.token != nil {
		// For refresh token sources, wrap with ReuseTokenSource for caching
		return oauth2.ReuseTokenSource(config.token, ts)
	}
	return ts
}

// tokenSource implements the oauth2.TokenSource interface. It provides a method to get an oauth2.Token using
// device auth through a call to RequestLiveToken.
type tokenSource struct {
	a *authclient.AuthClient
	w io.Writer
	t *oauth2.Token
	d Device
}

// Token attempts to return a Live Connect token using the RequestLiveToken function.
func (src *tokenSource) Token() (*oauth2.Token, error) {
	if src.t == nil {
		t, err := RequestLiveToken(WithWriter(src.w), WithDevice(src.d), WithAuthClient(src.a))
		src.t = t
		return t, err
	}
	tok, err := refreshToken(context.Background(), src.a, src.t, src.d)
	if err != nil {
		return nil, err
	}
	// Update the token to use to refresh for the next time Token is called.
	src.t = tok
	return tok, nil
}

// RefreshTokenSource returns a new oauth2.TokenSource using the oauth2.Token passed that automatically
// refreshes the token everytime it expires. Uses default device (DeviceAndroid) and writer (os.Stdout).
// Note that this function must be used over oauth2.ReuseTokenSource due to that function not refreshing
// with the correct scopes.
func RefreshTokenSource(t *oauth2.Token) oauth2.TokenSource {
	return NewTokenSource(WithToken(t))
}

// RequestLiveToken does a login request for Microsoft Live Connect using device auth with the given options.
// A login URL will be printed with a user code which the user must use to submit.
// Once fully authenticated, an oauth2 token is returned which may be used to login to XBOX Live.
// Default writer is os.Stdout, default device is DeviceAndroid.
func RequestLiveToken(opts ...TokenSourceOption) (*oauth2.Token, error) {
	return requestLiveTokenWithConfig(newTokenSourceConfig(opts...))
}

func requestLiveTokenWithConfig(config *tokenSourceConfig) (*oauth2.Token, error) {
	ctx := context.Background()
	d, err := StartDeviceAuth(ctx, config.authClient, config.device)
	if err != nil {
		return nil, err
	}

	_, _ = fmt.Fprintf(config.writer, "Authenticate at %v using the code %v.\n", d.VerificationURI, d.UserCode)
	ticker := time.NewTicker(time.Second * time.Duration(d.Interval))
	defer ticker.Stop()

	for range ticker.C {
		t, err := PollDeviceAuth(ctx, config.authClient, d.DeviceCode, config.device)
		if err != nil {
			return nil, fmt.Errorf("error polling for device auth: %w", err)
		}
		// If the token could not be obtained yet (authentication wasn't finished yet), the token is nil.
		// We just retry if this is the case.
		if t != nil {
			_, _ = config.writer.Write([]byte("Authentication successful.\n"))
			return t, nil
		}
	}
	// this case should never be reached
	return nil, fmt.Errorf("authentication timeout or cancelled")
}

var (
	serverTimeMu sync.Mutex
	// serverTime represents the most recent server date received from Microsoft servers.
	// It's used for the signed requests which can be blocked if the users device time is not synced.
	// It uses the date received from the unsigned requests.
	serverTime time.Time
)

func updateServerTimeFromHeaders(headers http.Header) {
	date := headers.Get("Date")
	if date == "" {
		return
	}
	t, err := time.Parse(time.RFC1123, date)
	if err != nil || t.IsZero() {
		return
	}
	serverTimeMu.Lock()
	serverTime = t
	serverTimeMu.Unlock()
}

// postFormRequest is a helper that creates and sends a POST request with form data.
func postFormRequest(ctx context.Context, authClient *authclient.AuthClient, url string, form url.Values) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create request for POST %s: %w", url, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := authclient.SendRequestWithRetries(ctx, authClient.HTTPClient(), req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", url, err)
	}
	return resp, nil
}

// StartDeviceAuth starts the device auth, retrieving a login URI for the user and a code the user needs to
// enter.
func StartDeviceAuth(ctx context.Context, authClient *authclient.AuthClient, deviceType Device) (*deviceAuthConnect, error) {
	const connectURL = "https://login.live.com/oauth20_connect.srf"
	resp, err := postFormRequest(ctx, authClient, connectURL, url.Values{
		"client_id":     {deviceType.ClientID},
		"scope":         {"service::user.auth.xboxlive.com::MBI_SSL"},
		"response_type": {"device_code"},
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("POST %s: %v", connectURL, resp.Status)
	}
	data := new(deviceAuthConnect)
	return data, json.NewDecoder(resp.Body).Decode(data)
}

func newOAuth2Token(poll *deviceAuthPoll) *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  poll.AccessToken,
		TokenType:    poll.TokenType,
		RefreshToken: poll.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(poll.ExpiresIn) * time.Second),
	}
}

// PollDeviceAuth polls the token endpoint for the device code. A token is returned if the user authenticated
// successfully. If the user has not yet authenticated, err is nil but the token is nil too.
func PollDeviceAuth(ctx context.Context, authClient *authclient.AuthClient, deviceCode string, deviceType Device) (t *oauth2.Token, err error) {
	resp, err := postFormRequest(ctx, authClient, microsoft.LiveConnectEndpoint.TokenURL, url.Values{
		"client_id":   {deviceType.ClientID},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	updateServerTimeFromHeaders(resp.Header)

	poll := new(deviceAuthPoll)
	if err := json.NewDecoder(resp.Body).Decode(poll); err != nil {
		return nil, fmt.Errorf("POST %s: json decode: %w", microsoft.LiveConnectEndpoint.TokenURL, err)
	}
	switch poll.Error {
	case "authorization_pending":
		return nil, nil
	case "":
		return newOAuth2Token(poll), nil
	default:
		return nil, fmt.Errorf("%v: %v", poll.Error, poll.ErrorDescription)
	}
}

// refreshToken refreshes the oauth2.Token passed and returns a new oauth2.Token. An error is returned if
// refreshing was not successful.
func refreshToken(ctx context.Context, authClient *authclient.AuthClient, t *oauth2.Token, deviceType Device) (*oauth2.Token, error) {
	// This function unfortunately needs to exist because golang.org/x/oauth2 does not pass the scope to this
	// request, which Microsoft Connect enforces.
	resp, err := postFormRequest(ctx, authClient, microsoft.LiveConnectEndpoint.TokenURL, url.Values{
		"client_id":     {deviceType.ClientID},
		"scope":         {"service::user.auth.xboxlive.com::MBI_SSL"},
		"grant_type":    {"refresh_token"},
		"refresh_token": {t.RefreshToken},
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	updateServerTimeFromHeaders(resp.Header)

	poll := new(deviceAuthPoll)
	if err := json.NewDecoder(resp.Body).Decode(poll); err != nil {
		return nil, fmt.Errorf("POST %s: json decode: %w", microsoft.LiveConnectEndpoint.TokenURL, err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("POST %s: refresh error: %v", microsoft.LiveConnectEndpoint.TokenURL, poll.Error)
	}
	return newOAuth2Token(poll), nil
}

type deviceAuthConnect struct {
	UserCode        string `json:"user_code"`
	DeviceCode      string `json:"device_code"`
	VerificationURI string `json:"verification_uri"`
	Interval        int    `json:"interval"`
	ExpiresIn       int    `json:"expires_in"`
}

type deviceAuthPoll struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	UserID           string `json:"user_id"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
}
