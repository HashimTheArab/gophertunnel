package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRequestMinecraftChainLeavesAuthHeadersToClient(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), cryptorand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	client := &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if got := req.Header.Get("Authorization"); got != "" {
			t.Fatalf("Authorization header = %q, want empty", got)
		}
		if got := req.Header.Get("Signature"); got != "" {
			t.Fatalf("Signature header = %q, want empty", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("chain")),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}

	chain, err := RequestMinecraftChain(context.Background(), client, key)
	if err != nil {
		t.Fatalf("RequestMinecraftChain: %v", err)
	}
	if chain != "chain" {
		t.Fatalf("chain = %q, want chain", chain)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
