package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/df-mc/go-xsapi/v2/xal/nsal"
	"github.com/df-mc/go-xsapi/v2/xal/xasu"
	"github.com/df-mc/go-xsapi/v2/xal/xsts"
)

type testTokenAndSignaturer struct {
	t *testing.T
}

func (s testTokenAndSignaturer) TokenAndSignature(_ context.Context, endpoint *url.URL) (*xsts.Token, nsal.SignaturePolicy, error) {
	s.t.Helper()
	if endpoint.String() != minecraftAuthURL.String() {
		s.t.Fatalf("TokenAndSignature endpoint = %q, want %q", endpoint, minecraftAuthURL)
	}
	return &xsts.Token{
		Token:    "token",
		NotAfter: time.Now().Add(time.Hour),
		DisplayClaims: xsts.DisplayClaims{UserInfo: []xsts.UserInfo{{
			UserInfo: xasu.UserInfo{UserHash: "user-hash"},
		}}},
	}, nsal.SignaturePolicy{}, nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestRequestMinecraftChainUsesNarrowAuthDependencies(t *testing.T) {
	client := &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if got, want := req.Header.Get("Authorization"), "XBL3.0 x=user-hash;token"; got != want {
			t.Fatalf("Authorization header = %q, want %q", got, want)
		}
		if got := req.Header.Get("Signature"); got != "" {
			t.Fatalf("Signature header = %q, want empty", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("chain")),
			Request:    req,
		}, nil
	})}
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	got, err := RequestMinecraftChain(context.Background(), testTokenAndSignaturer{t: t}, client, key)
	if err != nil {
		t.Fatal(err)
	}
	if got != "chain" {
		t.Fatalf("RequestMinecraftChain result = %q, want %q", got, "chain")
	}
}
