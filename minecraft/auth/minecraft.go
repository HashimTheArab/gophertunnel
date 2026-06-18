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
	"github.com/df-mc/go-xsapi/v2/xal/nsal"
	"github.com/df-mc/go-xsapi/v2/xal/xsts"
	"github.com/sandertv/gophertunnel/minecraft/auth/authclient"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// minecraftAuthURL is the URL that an authentication request is made to to get an encoded JWT claim chain.
var minecraftAuthURL = &url.URL{
	Scheme: "https",
	Host:   "multiplayer.minecraft.net",
	Path:   "/authentication",
} // https://multiplayer.minecraft.net/authentication

const xblRelyingParty = "http://xboxlive.com"

// RequestMinecraftChain requests a fully processed Minecraft JWT chain using the XSTS token passed, and the
// ECDSA private key of the client. This key will later be used to initialise encryption, and must be saved
// for when packets need to be decrypted/encrypted.
func RequestMinecraftChain(ctx context.Context, client *xsapi.Client, key *ecdsa.PrivateKey) (string, error) {
	return requestMinecraftChain(ctx, client.TokenAndSignature, client.HTTPClient(), client.TokenSource().ProofKey(), key)
}

// RequestMinecraftChainWithTokenSource requests a Minecraft JWT chain using the XSTS tokens supplied by src.
//
// Unlike [RequestMinecraftChain], this does not require a full Xbox Live API client and therefore does not
// connect to Xbox RTA services.
func RequestMinecraftChainWithTokenSource(ctx context.Context, src xsapi.TokenSource, key *ecdsa.PrivateKey) (string, error) {
	if src == nil {
		return "", fmt.Errorf("token source is nil")
	}
	ctx = withXBLHTTPClient(ctx, nil)
	return requestMinecraftChain(ctx, func(ctx context.Context, u *url.URL) (*xsts.Token, nsal.SignaturePolicy, error) {
		return TokenAndSignature(ctx, src, u)
	}, xal.ContextClient(ctx), src.ProofKey(), key)
}

type tokenAndSignatureFunc func(context.Context, *url.URL) (*xsts.Token, nsal.SignaturePolicy, error)

func requestMinecraftChain(ctx context.Context, tokenAndSignature tokenAndSignatureFunc, client *http.Client, proofKey, key *ecdsa.PrivateKey) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if client == nil {
		client = xblHTTPClient(ctx)
	}

	token, policy, err := tokenAndSignature(ctx, minecraftAuthURL)
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
	if err := policy.Sign(request, []byte(body), proofKey, xal.ServerTime()); err != nil {
		return "", fmt.Errorf("sign request: %w", err)
	}

	resp, err := authclient.SendRequestWithRetries(ctx, client, request, authclient.RetryOptions{Attempts: 5})
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

// TokenAndSignature resolves the XSTS token and signature policy for a URL without creating an xsapi.Client.
func TokenAndSignature(ctx context.Context, src xsapi.TokenSource, u *url.URL) (_ *xsts.Token, policy nsal.SignaturePolicy, _ error) {
	if src == nil {
		return nil, policy, fmt.Errorf("token source is nil")
	}
	ctx = withXBLHTTPClient(ctx, nil)

	authToken, err := src.XSTSToken(ctx, xblRelyingParty)
	if err != nil {
		return nil, policy, fmt.Errorf("request authorization token: %w", err)
	}
	resolver, err := nsal.NewResolver(ctx, authToken, src.ProofKey())
	if err != nil {
		return nil, policy, fmt.Errorf("request NSAL resolver: %w", err)
	}
	endpoint, policy, ok := resolver.Match(u)
	if !ok {
		return nil, policy, fmt.Errorf("no endpoint was found for %s", u)
	}
	token, err := src.XSTSToken(ctx, endpoint.RelyingParty)
	if err != nil {
		return nil, policy, fmt.Errorf("request XSTS token: %w", err)
	}
	return token, policy, nil
}
