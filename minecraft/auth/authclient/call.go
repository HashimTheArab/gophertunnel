package authclient

import (
	"context"
	"io"
	"net/http"
	"time"
)

// DefaultAttempts is how many times a request is sent when RetryOptions.Attempts is zero.
const DefaultAttempts = 3

// DefaultCallTimeout bounds a Call when CallOptions.Timeout is zero.
const DefaultCallTimeout = 40 * time.Second

// CallOptions bounds a Call and sets its retry policy.
type CallOptions struct {
	// Timeout bounds the call, from preparing the request until its response body is closed. Zero uses
	// DefaultCallTimeout.
	Timeout time.Duration
	// Stream bounds only preparing the request by Timeout, leaving sending and the body to ctx, for streamed
	// request or response bodies.
	Stream bool
	// Retry is the transient-failure policy passed to SendRequestWithRetries.
	Retry RetryOptions
}

// Call prepares a request under the call's deadline and sends it with SendRequestWithRetries. The deadline
// lasts until the response body is closed, so the caller must close it.
func Call(ctx context.Context, client *http.Client, prepare func(context.Context) (*http.Request, error), opts CallOptions) (*http.Response, error) {
	if client == nil {
		client = http.DefaultClient
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultCallTimeout
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	if err := callCtx.Err(); err != nil {
		cancel()
		return nil, err
	}
	req, err := prepare(callCtx)
	if err != nil {
		cancel()
		return nil, err
	}
	if opts.Stream {
		cancel()
		callCtx, cancel = ctx, func() {}
	}
	resp, err := SendRequestWithRetries(callCtx, client, req, opts.Retry)
	if err != nil {
		if resp != nil {
			_ = resp.Body.Close()
		}
		cancel()
		return nil, err
	}
	resp.Body = &callBody{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

// callBody keeps a Call's deadline alive until the response body is closed.
type callBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

// Close releases the call's context and closes the response body.
func (b *callBody) Close() error {
	b.cancel()
	return b.ReadCloser.Close()
}
