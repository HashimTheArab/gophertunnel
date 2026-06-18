package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/df-mc/go-xsapi/v2"
	"github.com/df-mc/go-xsapi/v2/xal"
	"github.com/sandertv/gophertunnel/minecraft/auth/authclient"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// minecraftAuthURL is the URL that an authentication request is made to to get an encoded JWT claim chain.
var minecraftAuthURL = &url.URL{
	Scheme: "https",
	Host:   "multiplayer.minecraft.net",
	Path:   "/authentication",
} // https://multiplayer.minecraft.net/authentication

// RequestMinecraftChain requests a fully processed Minecraft JWT chain using the XSTS token passed, and the
// ECDSA private key of the client. This key will later be used to initialise encryption, and must be saved
// for when packets need to be decrypted/encrypted.
func RequestMinecraftChain(ctx context.Context, client *xsapi.Client, key *ecdsa.PrivateKey) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	token, policy, err := client.TokenAndSignature(ctx, minecraftAuthURL)
	if err != nil {
		return "", fmt.Errorf("request token and signature: %w", err)
	}

	data, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}

	// The body of the requests holds a JSON object with one key in it, the 'identityPublicKey', which holds
	// the public key data of the private key passed.
	body := `{"identityPublicKey":"` + base64.StdEncoding.EncodeToString(data) + `"}`
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, minecraftAuthURL.String(), strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("POST %v: %w", minecraftAuthURL, err)
	}

	// The Authorization header is important in particular. It is composed of the 'uhs' found in the XSTS
	// token, and the Token it holds itself.
	token.SetAuthHeader(request)
	request.Header.Set("User-Agent", "MCPE/Android")
	request.Header.Set("Client-Version", protocol.CurrentVersion)
	request.Header.Set("Content-Type", "application/json")
	if err := policy.Sign(request, []byte(body), client.TokenSource().ProofKey(), xal.ServerTime()); err != nil {
		return "", fmt.Errorf("sign request: %w", err)
	}

	resp, err := authclient.SendRequestWithRetries(ctx, client.HTTPClient(), request, authclient.RetryOptions{Attempts: 5})
	if err != nil {
		return "", fmt.Errorf("POST %v: %w", minecraftAuthURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("POST %v: %v", minecraftAuthURL, resp.Status)
	}
	data, err = io.ReadAll(resp.Body)
	return string(data), err
}
