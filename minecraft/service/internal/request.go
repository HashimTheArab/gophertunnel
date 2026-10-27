package internal

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/sandertv/gophertunnel/minecraft/auth/authclient"
)

// CatalogCallTimeout bounds service calls, including authentication and retries.
const CatalogCallTimeout = 40 * time.Second

// CatalogRequestTimeout bounds each HTTP attempt, including reading its response body.
const CatalogRequestTimeout = 10 * time.Second

// CatalogRequestAttempts allows a retry while staying inside the call deadline.
const CatalogRequestAttempts = 2

// RequestOptions overrides the default service request bounds and retry policy.
type RequestOptions struct {
	// CallTimeout includes preparing the request, retries and reading the response body.
	// Zero or negative values use CatalogCallTimeout.
	CallTimeout time.Duration
	// RequestTimeout caps each HTTP attempt. A shorter client timeout is preserved.
	// Zero or negative values use CatalogRequestTimeout.
	RequestTimeout time.Duration
	// Retry controls transient retries. Zero Attempts uses CatalogRequestAttempts;
	// set Attempts to 1 for operations that must not be replayed.
	Retry authclient.RetryOptions
}

// SendRequest prepares and sends a bounded service request. A nil client selects the auth
// context's client. prepare must use its context for authentication and request creation.
// The caller must close the response body to release the call's context and timer.
func SendRequest(ctx context.Context, client *http.Client, prepare func(context.Context) (*http.Request, error), opts RequestOptions) (*http.Response, error) {
	callTimeout := opts.CallTimeout
	if callTimeout <= 0 {
		callTimeout = CatalogCallTimeout
	}
	requestTimeout := opts.RequestTimeout
	if requestTimeout <= 0 {
		requestTimeout = CatalogRequestTimeout
	}
	if opts.Retry.Attempts <= 0 {
		opts.Retry.Attempts = CatalogRequestAttempts
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	if err := ctx.Err(); err != nil {
		cancel()
		return nil, err
	}
	if client == nil {
		client = auth.ContextClient(ctx)
	}
	bounded := *client
	if bounded.Timeout <= 0 || bounded.Timeout > requestTimeout {
		bounded.Timeout = requestTimeout
	}
	req, err := prepare(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	resp, err := authclient.SendRequestWithRetries(ctx, &bounded, req, opts.Retry)
	if err != nil {
		cancel()
		return resp, err
	}
	resp.Body = &requestBody{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

// requestBody keeps the call deadline alive until the response body is closed.
type requestBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

// Close releases the call context and closes the underlying response body.
func (b *requestBody) Close() error {
	b.cancel()
	return b.ReadCloser.Close()
}
