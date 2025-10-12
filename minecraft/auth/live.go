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
// a code. TokenSource prints the authentication code and URL to os.Stdout. To use a different io.Writer, use
// WriterTokenSource. TokenSource automatically refreshes tokens.
var TokenSource oauth2.TokenSource = &tokenSource{w: os.Stdout}

// WriterTokenSource calls [WriterTokenSourceDevice] with the default device info.
func WriterTokenSource(w io.Writer) oauth2.TokenSource {
	return WriterTokenSourceDevice(w, DeviceAndroid)
}

// WriterTokenSourceDevice returns a new oauth2.TokenSource which, like TokenSource, uses device auth to get a code.
// Unlike TokenSource, WriterTokenSourceDevice allows passing an io.Writer to which information on the auth URL and
// code are printed. WriterTokenSourceDevice automatically refreshes tokens.
func WriterTokenSourceDevice(w io.Writer, d Device) oauth2.TokenSource {
	return &tokenSource{w: w, d: d}
}

// tokenSource implements the oauth2.TokenSource interface. It provides a method to get an oauth2.Token using
// device auth through a call to RequestLiveToken.
type tokenSource struct {
	w io.Writer
	t *oauth2.Token
	d Device
}

// Token attempts to return a Live Connect token using the RequestLiveToken function.
func (src *tokenSource) Token() (*oauth2.Token, error) {
	if src.t == nil {
		t, err := RequestLiveTokenWriterDevice(src.w, src.d)
		src.t = t
		return t, err
	}
	tok, err := refreshToken(context.Background(), authclient.DefaultClient, src.t, src.d)
	if err != nil {
		return nil, err
	}
	// Update the token to use to refresh for the next time Token is called.
	src.t = tok
	return tok, nil
}

// RefreshTokenSource calls [RefreshTokenSourceDevice] with the default device info.
func RefreshTokenSource(t *oauth2.Token) oauth2.TokenSource {
	return RefreshTokenSourceDevice(t, DeviceAndroid)
}

// RefreshTokenSourceDevice returns a new oauth2.TokenSource using the oauth2.Token passed that automatically
// refreshes the token everytime it expires. Note that this function must be used over oauth2.ReuseTokenSource
// due to that function not refreshing with the correct scopes.
func RefreshTokenSourceDevice(t *oauth2.Token, d Device) oauth2.TokenSource {
	return RefreshTokenSourceWriterDevice(t, os.Stdout, d)
}

// RefreshTokenSourceWriterDevice returns a new oauth2.TokenSource using the oauth2.Token passed that automatically
// refreshes the token everytime it expires. It requests from io.Writer if the oauth2.Token is invalid.
// Note that this function must be used over oauth2.ReuseTokenSource due to that
// function not refreshing with the correct scopes.
func RefreshTokenSourceWriterDevice(t *oauth2.Token, w io.Writer, d Device) oauth2.TokenSource {
	return oauth2.ReuseTokenSource(t, &tokenSource{w: w, t: t, d: d})
}

// RequestLiveToken calls [RequestLiveTokenDevice] with the default device info.
func RequestLiveToken() (*oauth2.Token, error) {
	return RequestLiveTokenDevice(DeviceAndroid)
}

// RequestLiveTokenDevice does a login request for Microsoft Live Connect using device auth. A login URL will be
// printed to the stdout with a user code which the user must use to submit.
// RequestLiveTokenDevice is the equivalent of RequestLiveTokenWriter(os.Stdout).
func RequestLiveTokenDevice(deviceType Device) (*oauth2.Token, error) {
	return RequestLiveTokenWriterDevice(os.Stdout, deviceType)
}

// RequestLiveTokenWriter calls [RequestLiveTokenWriterDevice] with the default device info.
func RequestLiveTokenWriter(w io.Writer) (*oauth2.Token, error) {
	return RequestLiveTokenWriterDevice(w, DeviceAndroid)
}

// RequestLiveTokenWriterDevice does a login request for Microsoft Live Connect using device auth. A login URL will
// be printed to the io.Writer passed with a user code which the user must use to submit.
// Once fully authenticated, an oauth2 token is returned which may be used to login to XBOX Live.
func RequestLiveTokenWriterDevice(w io.Writer, deviceType Device) (*oauth2.Token, error) {
	ctx := context.Background()
	d, err := StartDeviceAuth(ctx, deviceType)
	if err != nil {
		return nil, err
	}

	_, _ = fmt.Fprintf(w, "Authenticate at %v using the code %v.\n", d.VerificationURI, d.UserCode)
	ticker := time.NewTicker(time.Second * time.Duration(d.Interval))
	defer ticker.Stop()

	for range ticker.C {
		t, err := PollDeviceAuth(ctx, d.DeviceCode, deviceType)
		if err != nil {
			return nil, fmt.Errorf("error polling for device auth: %w", err)
		}
		// If the token could not be obtained yet (authentication wasn't finished yet), the token is nil.
		// We just retry if this is the case.
		if t != nil {
			_, _ = w.Write([]byte("Authentication successful.\n"))
			return t, nil
		}
	}
	panic("unreachable")
}

var (
	serverDate   time.Time
	serverDateMu sync.Mutex
)

func getDateHeader(headers http.Header) time.Time {
	date := headers.Get("Date")
	if date == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC1123, date); err == nil {
		return t
	}
	return time.Time{}
}

func setServerDate(d time.Time) {
	if !d.IsZero() {
		serverDateMu.Lock()
		serverDate = d
		serverDateMu.Unlock()
	}
}

// StartDeviceAuth starts the device auth, retrieving a login URI for the user and a code the user needs to
// enter.
func StartDeviceAuth(ctx context.Context, deviceType Device) (*deviceAuthConnect, error) {
	const connectURL = "https://login.live.com/oauth20_connect.srf"
	form := url.Values{
		"client_id":     {deviceType.ClientID},
		"scope":         {"service::user.auth.xboxlive.com::MBI_SSL"},
		"response_type": {"device_code"},
	}
	req, err := http.NewRequest("POST", connectURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create request for POST %s: %w", connectURL, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := authclient.SendRequestWithRetries(ctx, authclient.DefaultClient.HTTPClient(), req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", connectURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("POST %s: %v", connectURL, resp.Status)
	}
	data := new(deviceAuthConnect)
	return data, json.NewDecoder(resp.Body).Decode(data)
}

// PollDeviceAuth polls the token endpoint for the device code. A token is returned if the user authenticated
// successfully. If the user has not yet authenticated, err is nil but the token is nil too.
func PollDeviceAuth(ctx context.Context, deviceCode string, deviceType Device) (t *oauth2.Token, err error) {
	form := url.Values{
		"client_id":   {deviceType.ClientID},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
	}

	req, err := http.NewRequest("POST", microsoft.LiveConnectEndpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create request for POST %s: %w", microsoft.LiveConnectEndpoint.TokenURL, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := authclient.SendRequestWithRetries(ctx, authclient.DefaultClient.HTTPClient(), req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", microsoft.LiveConnectEndpoint.TokenURL, err)
	}
	defer resp.Body.Close()

	if d := getDateHeader(resp.Header); !d.IsZero() {
		setServerDate(d)
	}

	poll := new(deviceAuthPoll)
	if err := json.NewDecoder(resp.Body).Decode(poll); err != nil {
		return nil, fmt.Errorf("POST %s: json decode: %w", microsoft.LiveConnectEndpoint.TokenURL, err)
	}
	switch poll.Error {
	case "authorization_pending":
		return nil, nil
	case "":
		return &oauth2.Token{
			AccessToken:  poll.AccessToken,
			TokenType:    poll.TokenType,
			RefreshToken: poll.RefreshToken,
			Expiry:       time.Now().Add(time.Duration(poll.ExpiresIn) * time.Second),
		}, nil
	default:
		return nil, fmt.Errorf("%v: %v", poll.Error, poll.ErrorDescription)
	}
}

// refreshToken refreshes the oauth2.Token passed and returns a new oauth2.Token. An error is returned if
// refreshing was not successful.
func refreshToken(ctx context.Context, authClient *authclient.AuthClient, t *oauth2.Token, deviceType Device) (*oauth2.Token, error) {
	// This function unfortunately needs to exist because golang.org/x/oauth2 does not pass the scope to this
	// request, which Microsoft Connect enforces.
	form := url.Values{
		"client_id":     {deviceType.ClientID},
		"scope":         {"service::user.auth.xboxlive.com::MBI_SSL"},
		"grant_type":    {"refresh_token"},
		"refresh_token": {t.RefreshToken},
	}
	req, err := http.NewRequest("POST", microsoft.LiveConnectEndpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create request for POST %s: %w", microsoft.LiveConnectEndpoint.TokenURL, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := authclient.SendRequestWithRetries(ctx, authClient.HTTPClient(), req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", microsoft.LiveConnectEndpoint.TokenURL, err)
	}
	defer resp.Body.Close()

	if d := getDateHeader(resp.Header); !d.IsZero() {
		setServerDate(d)
	}

	poll := new(deviceAuthPoll)
	if err := json.NewDecoder(resp.Body).Decode(poll); err != nil {
		return nil, fmt.Errorf("POST %s: json decode: %w", microsoft.LiveConnectEndpoint.TokenURL, err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("POST %s: refresh error: %v", microsoft.LiveConnectEndpoint.TokenURL, poll.Error)
	}
	return &oauth2.Token{
		AccessToken:  poll.AccessToken,
		TokenType:    poll.TokenType,
		RefreshToken: poll.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(poll.ExpiresIn) * time.Second),
	}, nil
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
