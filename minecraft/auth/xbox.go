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
	AuthorizationToken struct {
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

	WebPage              string
	Sandbox              string
	UseModernGamertag    bool
	UcsMigrationResponse struct {
		GcsConsentsToOverride []string `json:"gcsConsentsToOverride"`
	}
	Flow string
}

// SetAuthHeader returns a string that may be used for the 'Authorization' header used for Minecraft
// related endpoints that need an XBOX Live authenticated caller.
func (t XBLToken) SetAuthHeader(r *http.Request) {
	r.Header.Set("Authorization", fmt.Sprintf("XBL3.0 x=%v;%v", t.AuthorizationToken.DisplayClaims.UserInfo[0].UserHash, t.AuthorizationToken.Token))
}

// RequestXBLToken requests an XBOX Live auth token using the passed Live token pair.
func (c *AuthClient) RequestXBLToken(ctx context.Context, liveToken *oauth2.Token, relyingParty string) (*XBLToken, error) {
	if !liveToken.Valid() {
		return nil, fmt.Errorf("live token is no longer valid")
	}

	// We first generate an ECDSA private key which will be used to provide a 'ProofKey' to each of the
	// requests, and to sign these requests.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ECDSA key: %w", err)
	}

	deviceToken, err := c.obtainDeviceToken(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("device token request failed: %w", err)
	}
	xblToken, err := c.obtainXBLToken(ctx, key, liveToken, deviceToken, relyingParty)
	if err != nil {
		return nil, fmt.Errorf("xbl token request failed: %w", err)
	}
	return xblToken, nil
}

func (c *AuthClient) obtainXBLToken(ctx context.Context, key *ecdsa.PrivateKey, liveToken *oauth2.Token, device *deviceToken, relyingParty string) (*XBLToken, error) {
	data, err := json.Marshal(map[string]any{
		"AccessToken":       "t=" + liveToken.AccessToken,
		"AppId":             AppID,
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
	sign(req, data, key)

	resp, err := c.DoWithOptions(ctx, req, RetryOptions{Attempts: 5})
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
func (c *AuthClient) obtainDeviceToken(ctx context.Context, key *ecdsa.PrivateKey) (token *deviceToken, err error) {
	data, err := json.Marshal(map[string]any{
		"RelyingParty": "http://auth.xboxlive.com",
		"TokenType":    "JWT",
		"Properties": map[string]any{
			"AuthMethod": "ProofOfPossession",
			"Id":         "{" + uuid.New().String() + "}",
			"DeviceType": DeviceType,
			"Version":    "10",
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
	sign(request, data, key)

	resp, err := c.DoWithOptions(ctx, request, RetryOptions{Attempts: 5})
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
func sign(request *http.Request, body []byte, key *ecdsa.PrivateKey) {
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
	_ = binary.Write(buf, binary.BigEndian, currentTime)
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
	r, s, _ := ecdsa.Sign(rand.Reader, key, hash.Sum(nil))
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])

	// The signature begins with 12 bytes, the first being the signature policy version (0, 0, 0, 1) again,
	// and the other 8 the timestamp again.
	buf = bytes.NewBuffer([]byte{0, 0, 0, 1})
	_ = binary.Write(buf, binary.BigEndian, currentTime)

	// Append the signature to the other 12 bytes, and encode the signature with standard base64 encoding.
	sig := append(buf.Bytes(), signature...)
	request.Header.Set("Signature", base64.StdEncoding.EncodeToString(sig))
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

// parseXboxError returns the message associated with an Xbox Live error code.
func parseXboxErrorCode(code string) string {
	switch code {
	case "2148916227":
		return "Your account was banned by Xbox for violating one or more Community Standards for Xbox and is unable to be used."
	case "2148916229":
		return "Your account is currently restricted and your guardian has not given you permission to play online. Login to https://account.microsoft.com/family/ and have your guardian change your permissions."
	case "2148916233":
		return "Your account currently does not have an Xbox profile. Please create one at https://signup.live.com/signup"
	case "2148916234":
		return "Your account has not accepted Xbox's Terms of Service. Please login and accept them."
	case "2148916235":
		return "Your account resides in a region that Xbox has not authorized use from. Xbox has blocked your attempt at logging in."
	case "2148916236":
		return "Your account requires proof of age. Please login to https://login.live.com/login.srf and provide proof of age."
	case "2148916237":
		return "Your account has reached its limit for playtime. Your account has been blocked from logging in."
	case "2148916238":
		return "The account date of birth is under 18 years and cannot proceed unless the account is added to a family by an adult."
	default:
		return fmt.Sprintf("unknown error code: %v", code)
	}
}
