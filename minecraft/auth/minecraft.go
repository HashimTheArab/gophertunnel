package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/df-mc/go-xsapi/v2"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// minecraftAuthURL is the URL that an authentication request is made to to get an encoded JWT claim chain.
var minecraftAuthURL = &url.URL{
	Scheme: "https",
	Host:   "multiplayer.minecraft.net",
	Path:   "/authentication",
} // https://multiplayer.minecraft.net/authentication

// RequestMinecraftChain requests a fully processed Minecraft JWT chain using
// signer and the ECDSA private key passed. The key will later be used to
// initialise encryption, and must be saved for when packets need to be
// decrypted/encrypted.
func RequestMinecraftChain(ctx context.Context, signer xsapi.TokenAndSignaturer, client *http.Client, key *ecdsa.PrivateKey) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if signer == nil {
		return "", errors.New("xbox live token signer is nil")
	}
	if client == nil {
		client = http.DefaultClient
	}

	token, _, err := signer.TokenAndSignature(ctx, minecraftAuthURL)
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

	token.SetAuthHeader(request)
	request.Header.Set("User-Agent", "MCPE/Android")
	request.Header.Set("Client-Version", protocol.CurrentVersion)
	request.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(request)
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
