package service

import (
	"context"
	"net/http"

	"github.com/sandertv/gophertunnel/minecraft/service/internal"
)

// RequestOptions overrides service call bounds and transient retry settings.
type RequestOptions = internal.RequestOptions

// SendRequest sends a bounded HTTP request through the shared service request helper.
// It allows sibling packages such as realms to use the same policy. prepare must use its
// context for authentication and request creation. A nil client uses the auth context's
// client. The caller must close the response body to release the call's context and timer.
func SendRequest(ctx context.Context, client *http.Client, prepare func(context.Context) (*http.Request, error), opts RequestOptions) (*http.Response, error) {
	return internal.SendRequest(ctx, client, prepare, opts)
}
