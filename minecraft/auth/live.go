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
var TokenSource oauth2.TokenSource = AndroidConfig.WriterTokenSource(os.Stdout)

// WriterTokenSource returns a new oauth2.TokenSource which, like TokenSource, uses device auth to get a code.
// Unlike TokenSource, WriterTokenSource allows passing an io.Writer to which information on the auth URL and
// code are printed. WriterTokenSource automatically refreshes tokens.
func WriterTokenSource(w io.Writer) oauth2.TokenSource {
	return AndroidConfig.WriterTokenSource(w)
}

func (conf Config) WriterTokenSource(w io.Writer) oauth2.TokenSource {
	return &tokenSource{w: w, conf: conf}
}

// tokenSource implements the oauth2.TokenSource interface. It provides a method to get an oauth2.Token using
// device auth through a call to RequestLiveToken.
//
// NOTE: tokenSource requires a Config field to be set, otherwise the device auth
// flow will send an invalid request and fail. Prefer constructing via [Config.WriterTokenSource] (or
// [AndroidConfig.WriterTokenSource]) rather than instantiating tokenSource directly.
type tokenSource struct {
	w    io.Writer
	t    *oauth2.Token
	conf Config
}

// Token attempts to return a Live Connect token using the RequestLiveToken function.
func (src *tokenSource) Token() (*oauth2.Token, error) {
	if src.conf.ClientID == "" {
		panic(fmt.Errorf("minecraft/auth: tokenSource: missing ClientID; construct via Config.WriterTokenSource (or AndroidConfig.WriterTokenSource)"))
	}
	if src.t == nil {
		t, err := src.conf.RequestLiveTokenWriter(src.w)
		src.t = t
		return t, err
	}
	tok, err := src.conf.refreshToken(context.Background(), src.t)
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
	return RefreshTokenSourceWriter(t, os.Stdout)
}

// RefreshTokenSource returns a new oauth2.TokenSource using the oauth2.Token passed that automatically
// refreshes the token everytime it expires. Note that this function must be used over oauth2.ReuseTokenSource
// due to that function not refreshing with the correct scopes.
func (conf Config) RefreshTokenSource(t *oauth2.Token) oauth2.TokenSource {
	return conf.RefreshTokenSourceWriter(t, os.Stdout)
}

// RefreshTokenSourceWriter returns a new oauth2.TokenSource using the oauth2.Token passed that automatically
// refreshes the token everytime it expires. It requests from io.Writer if the oauth2.Token is invalid.
// Note that this function must be used over oauth2.ReuseTokenSource due to that
// function not refreshing with the correct scopes.
func RefreshTokenSourceWriter(t *oauth2.Token, w io.Writer) oauth2.TokenSource {
	return AndroidConfig.RefreshTokenSourceWriter(t, w)
}

// RefreshTokenSourceWriter returns a new oauth2.TokenSource using the oauth2.Token passed that automatically
// refreshes the token everytime it expires. It requests from io.Writer if the oauth2.Token is invalid.
// Note that this function must be used over oauth2.ReuseTokenSource due to that
// function not refreshing with the correct scopes.
func (conf Config) RefreshTokenSourceWriter(t *oauth2.Token, w io.Writer) oauth2.TokenSource {
	return oauth2.ReuseTokenSource(t, &tokenSource{w: w, t: t, conf: conf})
}

// RequestLiveToken does a login request for Microsoft Live Connect using device auth. A login URL will be
// printed to the stdout with a user code which the user must use to submit.
// RequestLiveToken is the equivalent of RequestLiveTokenWriter(os.Stdout).
func RequestLiveToken() (*oauth2.Token, error) {
	return RequestLiveTokenWriter(os.Stdout)
}

// RequestLiveToken does a login request for Microsoft Live Connect using device auth. A login URL will be
// printed to the stdout with a user code which the user must use to submit.
// RequestLiveToken is the equivalent of RequestLiveTokenWriter(os.Stdout).
func (conf Config) RequestLiveToken() (*oauth2.Token, error) {
	return conf.RequestLiveTokenWriter(os.Stdout)
}

// RequestLiveTokenWriter does a login request for Microsoft Live Connect using device auth. A login URL will
// be printed to the io.Writer passed with a user code which the user must use to submit.
// Once fully authenticated, an oauth2 token is returned which may be used to login to XBOX Live.
func RequestLiveTokenWriter(w io.Writer) (*oauth2.Token, error) {
	return AndroidConfig.RequestLiveTokenWriter(w)
}

// RequestLiveTokenWriter does a login request for Microsoft Live Connect using device auth. A login URL will
// be printed to the io.Writer passed with a user code which the user must use to submit.
// Once fully authenticated, an oauth2 token is returned which may be used to login to XBOX Live.
func (conf Config) RequestLiveTokenWriter(w io.Writer) (*oauth2.Token, error) {
	ctx := context.Background()
	d, err := conf.StartDeviceAuth(ctx)
	if err != nil {
		return nil, err
	}

	_, _ = fmt.Fprintf(w, "Authenticate at %v using the code %v.\n", d.VerificationURI, d.UserCode)
	ticker := time.NewTicker(time.Second * time.Duration(d.Interval))
	defer ticker.Stop()

	for range ticker.C {
		t, err := conf.PollDeviceAuth(ctx, d.DeviceCode)
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
	// this case should never be reached
	return nil, fmt.Errorf("authentication timeout or cancelled")
}

var (
	serverTimeMu sync.Mutex
	// serverTimeDelta is the offset to add to time.Now() to approximate Microsoft's server time, based on the
	// most recent Date header we received.
	//
	// Signed Xbox Live requests can be rejected if the client timestamp is too far from server time.
	serverTimeDelta time.Duration

	// deviceAuthBackoff holds additional delay to apply (per device code) after the server responds with
	// "slow_down" (RFC 8628). This allows callers to keep using a fixed ticker interval while still honoring
	// the server's request to back off.
	deviceAuthBackoff sync.Map // map[string]time.Duration
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
	serverTimeDelta = time.Until(t)
	serverTimeMu.Unlock()
}

// postFormRequest is a helper that creates and sends a POST request with form data.
func postFormRequest(ctx context.Context, url string, form url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create request for POST %s: %w", url, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := authclient.SendRequestWithRetries(ctx, xblHTTPClient(ctx), req, authclient.RetryOptions{Attempts: 5})
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", url, err)
	}
	return resp, nil
}

// StartDeviceAuth starts the device auth, retrieving a login URI for the user and a code the user needs to
// enter. The returned DeviceAuthResponse contains the verification URI and user code to present to the user.
// Use PollDeviceAuth with the DeviceCode to poll for completion.
func (conf Config) StartDeviceAuth(ctx context.Context) (*DeviceAuthConnect, error) {
	if conf.ClientID == "" {
		panic(fmt.Errorf("minecraft/auth: missing ClientID for device auth"))
	}
	const connectURL = "https://login.live.com/oauth20_connect.srf"
	resp, err := postFormRequest(ctx, connectURL, url.Values{
		"client_id":     {conf.ClientID},
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
	data := new(DeviceAuthConnect)
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
func (conf Config) PollDeviceAuth(ctx context.Context, deviceCode string) (t *oauth2.Token, err error) {
	// Honor any server-requested backoff. This delays the *next* poll request without requiring callers to
	// mutate their polling ticker interval.
	if v, ok := deviceAuthBackoff.Load(deviceCode); ok {
		if d, ok := v.(time.Duration); ok && d > 0 {
			timer := time.NewTimer(d)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
	}

	resp, err := postFormRequest(ctx, microsoft.LiveConnectEndpoint.TokenURL, url.Values{
		"client_id":   {conf.ClientID},
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
	case "slow_down":
		// RFC 8628 instructs clients to increase the poll interval by 5 seconds for all subsequent requests.
		// We implement this as an additional per-device-code delay inside PollDeviceAuth so callers don't need
		// to special-case this error.
		var current time.Duration
		if v, ok := deviceAuthBackoff.Load(deviceCode); ok {
			if d, ok := v.(time.Duration); ok {
				current = d
			}
		}
		deviceAuthBackoff.Store(deviceCode, current+5*time.Second)
		return nil, nil
	case "":
		deviceAuthBackoff.Delete(deviceCode)
		return newOAuth2Token(poll), nil
	default:
		deviceAuthBackoff.Delete(deviceCode)
		return nil, fmt.Errorf("%v: %v", poll.Error, poll.ErrorDescription)
	}
}

// refreshToken refreshes the oauth2.Token passed and returns a new oauth2.Token. An error is returned if
// refreshing was not successful.
func (conf Config) refreshToken(ctx context.Context, t *oauth2.Token) (*oauth2.Token, error) {
	// This function unfortunately needs to exist because golang.org/x/oauth2 does not pass the scope to this
	// request, which Microsoft Connect enforces.
	resp, err := postFormRequest(ctx, microsoft.LiveConnectEndpoint.TokenURL, url.Values{
		"client_id":     {conf.ClientID},
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

// DeviceAuthConnect contains the response from starting device authentication.
// It includes the user code and verification URI that should be presented to the user.
type DeviceAuthConnect struct {
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
