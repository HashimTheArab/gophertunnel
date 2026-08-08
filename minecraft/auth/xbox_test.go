package auth

import (
	"context"
	"net/http"
	"testing"

	"github.com/df-mc/go-xsapi/v2/xal"
	"golang.org/x/oauth2"
)

func TestWithContextClientStoresProvidedClient(t *testing.T) {
	client := &http.Client{}
	ctx := WithContextClient(context.Background(), client)

	if got := ContextClient(ctx); got != client {
		t.Fatalf("ContextClient(WithContextClient(...)) = %p, want %p", got, client)
	}
	if got := ctx.Value(oauth2.HTTPClient); got != client {
		t.Fatalf("OAuth2 context client = %p, want %p", got, client)
	}
	if got := ctx.Value(xal.HTTPClient); got != client {
		t.Fatalf("XAL context client = %p, want %p", got, client)
	}
}

func TestWithContextClientPreservesExistingClient(t *testing.T) {
	existing := &http.Client{}
	provided := &http.Client{}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, existing)
	ctx = WithContextClient(ctx, provided)

	if got := ContextClient(ctx); got != existing {
		t.Fatalf("ContextClient(WithContextClient(...)) = %p, want existing %p", got, existing)
	}
	if got := ctx.Value(xal.HTTPClient); got != existing {
		t.Fatalf("XAL context client = %p, want existing %p", got, existing)
	}
}
