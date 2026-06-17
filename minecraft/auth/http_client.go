package auth

import (
	"context"
	"net/http"

	"github.com/df-mc/go-xsapi/v2/xal"
	"golang.org/x/oauth2"
)

func withXBLHTTPClient(ctx context.Context, client *http.Client) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if client == nil {
		if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok && c != nil {
			client = c
		} else if c, ok := ctx.Value(xal.HTTPClient).(*http.Client); ok && c != nil {
			client = c
		} else {
			client = http.DefaultClient
		}
	}
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); !ok || c == nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	}
	if c, ok := ctx.Value(xal.HTTPClient).(*http.Client); !ok || c == nil {
		ctx = context.WithValue(ctx, xal.HTTPClient, client)
	}
	return ctx
}
