package auth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/auth/authclient"
	"golang.org/x/oauth2"
)

// XBLToken holds info on the authorization token used for authenticating with XBOX Live.
type XBLToken struct {
	TitleToken struct {
		DisplayClaims struct {
			Xti struct {
				TitleID string `json:"tid"`
			} `json:"xti"`
		}
		IssueInstant time.Time
		NotAfter     time.Time
		Token        string
	} `json:"TitleToken"`

	UserToken struct {
		DisplayClaims struct {
			Xui []struct {
				UserHash string `json:"uhs"`
			} `json:"xui"`
		}
		IssueInstant time.Time
		NotAfter     time.Time
		Token        string
	} `json:"UserToken"`

	// AuthorizationToken is the token used for the authorization header for Xbox API requests.
	AuthorizationToken authorizationToken

	WebPage              string
	Sandbox              string
	UseModernGamertag    bool
	UcsMigrationResponse struct {
		GcsConsentsToOverride []string `json:"gcsConsentsToOverride"`
	}
	Flow string
}

type authorizationToken struct {
	DisplayClaims struct {
		UserInfo []struct {
			GamerTag string `json:"gtg"`
			XUID     string `json:"xid"`
			UserHash string `json:"uhs"`
		} `json:"xui"`
	}
	IssueInstant time.Time
	NotAfter     time.Time
	Token        string
}

func (t authorizationToken) Expired() bool {
	return time.Now().After(t.NotAfter.Add(-time.Minute * 5))
}

// SetAuthHeader returns a string that may be used for the 'Authorization' header used for Minecraft
// related endpoints that need an XBOX Live authenticated caller.
func (t XBLToken) SetAuthHeader(r *http.Request) {
	if len(t.AuthorizationToken.DisplayClaims.UserInfo) == 0 {
		panic("xbox: authorization token has no user info (malformed response from Microsoft)")
	}
	r.Header.Set("Authorization", fmt.Sprintf("XBL3.0 x=%v;%v", t.AuthorizationToken.DisplayClaims.UserInfo[0].UserHash, t.AuthorizationToken.Token))
}

// XBLTokenObtainer holds a live token and device token used for requesting XBL tokens.
type XBLTokenObtainer struct {
	authClient  *authclient.AuthClient
	key         *ecdsa.PrivateKey
	liveToken   *oauth2.Token
	src         oauth2.TokenSource
	deviceToken *deviceToken
	deviceType  Device
}

// NewXBLTokenObtainer creates a new XBLTokenObtainer from the live token and token source passed.
func NewXBLTokenObtainer(ctx context.Context, deviceType Device, authClient *authclient.AuthClient, liveToken *oauth2.Token, src oauth2.TokenSource) (*XBLTokenObtainer, error) {
	if !liveToken.Valid() {
		return nil, fmt.Errorf("live token is no longer valid")
	}
	// We first generate an ECDSA private key which will be used to provide a 'ProofKey' to each of the
	// requests, and to sign these requests.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ECDSA key: %w", err)
	}
	deviceToken, err := obtainDeviceToken(ctx, authClient, key, deviceType)
	if err != nil {
		return nil, err
	}
	return &XBLTokenObtainer{key: key, deviceToken: deviceToken, liveToken: liveToken, src: src, deviceType: deviceType, authClient: authClient}, nil
}

// RequestXBLToken requests an XBL token using the pair stored in the obtainer.
// It automatically refreshes the live token if it has expired.
func (x *XBLTokenObtainer) RequestXBLToken(ctx context.Context, relyingParty string) (*XBLToken, error) {
	if !x.liveToken.Valid() {
		tok, err := x.src.Token()
		if err != nil {
			return nil, fmt.Errorf("refresh live token: %w", err)
		}
		x.liveToken = tok
	}
	if time.Now().After(x.deviceToken.NotAfter) {
		return nil, fmt.Errorf("device token is no longer valid") // dont refresh for now, device token stays valid for 14 days
	}
	return obtainXBLToken(ctx, x.authClient, x.key, x.liveToken, x.deviceToken, x.deviceType, relyingParty)
}

// RequestXBLToken calls [RequestXBLTokenDevice] with the default device info.
func RequestXBLToken(ctx context.Context, authClient *authclient.AuthClient, liveToken *oauth2.Token, relyingParty string) (*XBLToken, error) {
	return RequestXBLTokenDevice(ctx, authClient, liveToken, DeviceAndroid, relyingParty)
}

// RequestXBLTokenDevice requests an XBOX Live auth token using the passed Live token pair.
func RequestXBLTokenDevice(ctx context.Context, authClient *authclient.AuthClient, liveToken *oauth2.Token, deviceType Device, relyingParty string) (*XBLToken, error) {
	if !liveToken.Valid() {
		return nil, fmt.Errorf("live token is no longer valid")
	}
	// We first generate an ECDSA private key which will be used to provide a 'ProofKey' to each of the
	// requests, and to sign these requests.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ECDSA key: %w", err)
	}
	deviceToken, err := obtainDeviceToken(ctx, authClient, key, deviceType)
	if err != nil {
		return nil, fmt.Errorf("device token request failed: %w", err)
	}
	xblToken, err := obtainXBLToken(ctx, authClient, key, liveToken, deviceToken, deviceType, relyingParty)
	if err != nil {
		return nil, fmt.Errorf("xbl token request failed: %w", err)
	}
	return xblToken, nil
}

func obtainXBLToken(ctx context.Context, c *authclient.AuthClient, key *ecdsa.PrivateKey, liveToken *oauth2.Token, device *deviceToken, deviceType Device, relyingParty string) (*XBLToken, error) {
	data, err := json.Marshal(map[string]any{
		"AccessToken":       "t=" + liveToken.AccessToken,
		"AppId":             deviceType.ClientID,
		"DeviceToken":       device.Token,
		"Sandbox":           "RETAIL",
		"UseModernGamertag": true,
		"SiteName":          "user.auth.xboxlive.com",
		"RelyingParty":      relyingParty,
		"ProofKey": map[string]any{
			"crv": "P-256",
			"alg": "ES256",
			"use": "sig",
			"kty": "EC",
			"x":   base64.RawURLEncoding.EncodeToString(padTo32Bytes(key.PublicKey.X)),
			"y":   base64.RawURLEncoding.EncodeToString(padTo32Bytes(key.PublicKey.Y)),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling XBL auth request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://sisu.xboxlive.com/authorize", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("POST %v: %w", "https://sisu.xboxlive.com/authorize", err)
	}
	req.Header.Set("x-xbl-contract-version", "1")
	if err := sign(req, data, key); err != nil {
		return nil, fmt.Errorf("signing XBL auth request: %w", err)
	}

	resp, err := c.DoWithOptions(ctx, req, authclient.RetryOptions{Attempts: 5})
	if err != nil {
		var body []byte
		if resp != nil && resp.Body != nil {
			body, _ = io.ReadAll(resp.Body)
		}
		return nil, newXboxNetworkError("POST", "https://sisu.xboxlive.com/authorize", err, body)
	}
	defer resp.Body.Close()

	if d := getDateHeader(resp.Header); !d.IsZero() {
		setServerDate(d)
	}

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, newXboxHTTPError("POST", "https://sisu.xboxlive.com/authorize", resp, body)
	}
	info := new(XBLToken)
	return info, json.NewDecoder(resp.Body).Decode(info)
}

// deviceToken is the token obtained by requesting a device token by posting to xblDeviceAuthURL. Its Token
// field may be used in a request to obtain the XSTS token.
type deviceToken struct {
	// IssueInstant is the time the token was issued at.
	IssueInstant time.Time
	// NotAfter is the expiration time of the device token.
	NotAfter      time.Time
	Token         string
	DisplayClaims struct {
		XDI struct {
			DID string `json:"did"`
			DCS string `json:"dcs"`
		} `json:"xdi"`
	}
}

// obtainDeviceToken sends a POST request to the device auth endpoint using the ECDSA private key passed to
// sign the request.
func obtainDeviceToken(ctx context.Context, c *authclient.AuthClient, key *ecdsa.PrivateKey, deviceType Device) (token *deviceToken, err error) {
	data, err := json.Marshal(map[string]any{
		"RelyingParty": "http://auth.xboxlive.com",
		"TokenType":    "JWT",
		"Properties": map[string]any{
			"AuthMethod": "ProofOfPossession",
			"Id":         "{" + uuid.New().String() + "}",
			"DeviceType": deviceType.DeviceType,
			"Version":    deviceType.Version,
			"ProofKey": map[string]any{
				"crv": "P-256",
				"alg": "ES256",
				"use": "sig",
				"kty": "EC",
				"x":   base64.RawURLEncoding.EncodeToString(padTo32Bytes(key.PublicKey.X)),
				"y":   base64.RawURLEncoding.EncodeToString(padTo32Bytes(key.PublicKey.Y)),
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling device auth request: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, "POST", "https://device.auth.xboxlive.com/device/authenticate", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("POST %v: %w", "https://device.auth.xboxlive.com/device/authenticate", err)
	}

	request.Header.Set("Cache-Control", "no-store, must-revalidate, no-cache")
	request.Header.Set("x-xbl-contract-version", "1")
	if err := sign(request, data, key); err != nil {
		return nil, fmt.Errorf("signing device auth request: %w", err)
	}

	resp, err := c.DoWithOptions(ctx, request, authclient.RetryOptions{Attempts: 5})
	if err != nil {
		var body []byte
		if resp != nil && resp.Body != nil {
			body, _ = io.ReadAll(resp.Body)
		}
		return nil, newXboxNetworkError("POST", "https://device.auth.xboxlive.com/device/authenticate", err, body)
	}

	if d := getDateHeader(resp.Header); !d.IsZero() {
		setServerDate(d)
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, newXboxHTTPError("POST", "https://device.auth.xboxlive.com/device/authenticate", resp, body)
	}
	token = new(deviceToken)
	return token, json.NewDecoder(resp.Body).Decode(token)
}

// sign signs the request passed containing the body passed. It signs the request using the ECDSA private key
// passed. If the request has a 'ProofKey' field in the Properties field, that key must be passed here.
func sign(request *http.Request, body []byte, key *ecdsa.PrivateKey) error {
	var currentTime int64
	serverDateMu.Lock()
	currentServerDate := serverDate
	serverDateMu.Unlock()
	if !currentServerDate.IsZero() {
		currentTime = windowsTimestamp(currentServerDate)
	} else { // Should never happen
		currentTime = windowsTimestamp(time.Now())
	}

	hash := sha256.New()

	// Signature policy version (0, 0, 0, 1) + 0 byte.
	buf := bytes.NewBuffer([]byte{0, 0, 0, 1, 0})
	// Timestamp + 0 byte.
	if err := binary.Write(buf, binary.BigEndian, currentTime); err != nil {
		return fmt.Errorf("writing current time: %w", err)
	}
	buf.Write([]byte{0})
	hash.Write(buf.Bytes())

	// HTTP method, generally POST + 0 byte.
	hash.Write([]byte("POST"))
	hash.Write([]byte{0})
	// Request uri path + raw query + 0 byte.
	path := request.URL.Path
	if rq := request.URL.RawQuery; rq != "" {
		path += "?" + rq
	}
	hash.Write([]byte(path))
	hash.Write([]byte{0})

	// Authorization header if present, otherwise an empty string + 0 byte.
	hash.Write([]byte(request.Header.Get("Authorization")))
	hash.Write([]byte{0})

	// Body data (only up to a certain limit, but this limit is practically never reached) + 0 byte.
	hash.Write(body)
	hash.Write([]byte{0})

	// Sign the checksum produced, and combine the 'r' and 's' into a single signature.
	// Encode r and s as 32-byte, zero-padded big-endian values so the P-256 signature is always exactly 64 bytes long.
	r, s, err := ecdsa.Sign(rand.Reader, key, hash.Sum(nil))
	if err != nil {
		return fmt.Errorf("signing hash: %w", err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])

	// The signature begins with 12 bytes, the first being the signature policy version (0, 0, 0, 1) again,
	// and the other 8 the timestamp again.
	buf = bytes.NewBuffer([]byte{0, 0, 0, 1})
	if err := binary.Write(buf, binary.BigEndian, currentTime); err != nil {
		return fmt.Errorf("writing current time: %w", err)
	}

	// Append the signature to the other 12 bytes, and encode the signature with standard base64 encoding.
	sig := append(buf.Bytes(), signature...)
	request.Header.Set("Signature", base64.StdEncoding.EncodeToString(sig))
	return nil
}

// windowsTimestamp returns a Windows specific timestamp. It has a certain offset from Unix time which must be
// accounted for.
func windowsTimestamp(t time.Time) int64 {
	return (t.Unix() + 11644473600) * 10000000
}

// padTo32Bytes converts a big.Int into a fixed 32-byte, zero-padded slice.
// This is used to ensure that the X and Y coordinates of the ECDSA public key are always 32 bytes long,
// because big.Int.Bytes() returns a minimal encoding which may sometimes be less than 32 bytes.
func padTo32Bytes(b *big.Int) []byte {
	out := make([]byte, 32)
	b.FillBytes(out)
	return out
}
