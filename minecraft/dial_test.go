package minecraft

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/df-mc/go-xsapi/v2/xal"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"golang.org/x/oauth2"
)

func TestDialAuthContextPropagatesHTTPClient(t *testing.T) {
	t.Parallel()

	client := &http.Client{}
	ctx := withDialAuthHTTPClient(context.Background(), client)

	if got, _ := ctx.Value(xal.HTTPClient).(*http.Client); got != client {
		t.Fatalf("xal.HTTPClient = %p, want %p", got, client)
	}
	if got, _ := ctx.Value(oauth2.HTTPClient).(*http.Client); got != client {
		t.Fatalf("oauth2.HTTPClient = %p, want %p", got, client)
	}
}

func TestDialAuthContextDoesNotOverwriteHTTPClient(t *testing.T) {
	t.Parallel()

	existingXAL := &http.Client{}
	existingOAuth := &http.Client{}
	replacement := &http.Client{}
	ctx := context.WithValue(context.Background(), xal.HTTPClient, existingXAL)
	ctx = context.WithValue(ctx, oauth2.HTTPClient, existingOAuth)
	ctx = withDialAuthHTTPClient(ctx, replacement)

	if got, _ := ctx.Value(xal.HTTPClient).(*http.Client); got != existingXAL {
		t.Fatalf("xal.HTTPClient = %p, want existing %p", got, existingXAL)
	}
	if got, _ := ctx.Value(oauth2.HTTPClient).(*http.Client); got != existingOAuth {
		t.Fatalf("oauth2.HTTPClient = %p, want existing %p", got, existingOAuth)
	}
}

func TestHandleNetworkSettingsRejectsUnknownCompression(t *testing.T) {
	t.Parallel()

	conn := &Conn{}
	err := conn.handleNetworkSettings(&packet.NetworkSettings{CompressionAlgorithm: 255})
	if err == nil || !strings.Contains(err.Error(), "unknown compression algorithm") {
		t.Fatalf("handleNetworkSettings error = %v, want unknown compression error", err)
	}
}

func TestReadChainIdentityDataRejectsShortChain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data string
	}{
		{name: "empty", data: `{"chain":[]}`},
		{name: "one entry", data: `{"chain":["root"]}`},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := readChainIdentityData([]byte(tt.data)); err == nil {
				t.Fatal("expected short chain error")
			}
		})
	}
}
