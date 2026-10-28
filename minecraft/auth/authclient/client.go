package authclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"time"
)

type RetryOptions struct {
	Attempts int           // how many times to send the request (default: DefaultAttempts)
	Factor   float64       // factor to multiply the delay by on each attempt (default: 2.0)
	MinDelay time.Duration // minimum delay (default: 500ms)
	MaxDelay time.Duration // Maximum delay (default: 8s)
	// Replayable marks a request that may be sent again even if a previous attempt may have reached the
	// server, such as a read-only POST. Idempotent methods and idempotency keys are replayable already.
	Replayable bool
}

// SendRequestWithRetries sends a request and retries on 429, 408, 5xx and network errors. A request is only
// sent again if it is replayable, unless the server rejected it unprocessed with a 429, or a 503 carrying
// Retry-After. A retry delay that would end after ctx's deadline returns the last outcome instead of waiting.
func SendRequestWithRetries(ctx context.Context, c *http.Client, request *http.Request, r ...RetryOptions) (*http.Response, error) {
	var opts RetryOptions
	if len(r) > 0 {
		opts = r[0]
	}
	if opts.Attempts <= 0 {
		opts.Attempts = DefaultAttempts
	}
	if opts.Factor <= 0 {
		opts.Factor = 2.0
	}
	if opts.MinDelay <= 0 {
		opts.MinDelay = 500 * time.Millisecond
	}
	if opts.MaxDelay <= 0 {
		opts.MaxDelay = 8 * time.Second
	}
	if opts.MaxDelay < opts.MinDelay {
		opts.MaxDelay = opts.MinDelay
	}

	for i := 1; ; i++ {
		req := request.Clone(ctx)
		if request.Body != nil && request.GetBody != nil {
			body, err := request.GetBody()
			if err != nil {
				return nil, err
			}
			req.Body = body
		}

		resp, err := c.Do(req)
		if err != nil && ctx.Err() != nil && !errors.Is(err, ctx.Err()) {
			err = fmt.Errorf("%w: %w", ctx.Err(), err)
		}
		if ctx.Err() != nil || i >= opts.Attempts || !retryable(request, opts.Replayable, resp, err) {
			return resp, err
		}
		var retryAfter time.Duration
		if resp != nil {
			if seconds, parseErr := strconv.Atoi(resp.Header.Get("Retry-After")); parseErr == nil {
				retryAfter = time.Duration(seconds) * time.Second
			}
		}

		delay := max(min(opts.MinDelay*time.Duration(math.Pow(opts.Factor, float64(i))), opts.MaxDelay), retryAfter)
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= delay {
			// Waiting would end after the deadline, so the last outcome is more useful than a deadline error.
			return resp, err
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
	}
}

// retryable reports whether an attempt that ended with resp or err may be sent again: only if repeating it
// is safe, or the server refused it unprocessed with a 429, or a 503 with Retry-After. Edges such as Azure
// Front Door also send a bare 503 after the origin timed out.
func retryable(req *http.Request, replayable bool, resp *http.Response, err error) bool {
	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		return false // the body cannot be sent again
	}
	switch req.Method {
	case "", http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace, http.MethodPut, http.MethodDelete:
		replayable = true
	}
	_, key := req.Header["Idempotency-Key"]
	_, xKey := req.Header["X-Idempotency-Key"]
	replayable = replayable || key || xKey

	if err != nil {
		// Some proxies close the connection without a response, which often surfaces as EOF.
		_, netErr := errors.AsType[net.Error](err)
		return (netErr || errors.Is(err, io.EOF)) && replayable
	}
	switch code := resp.StatusCode; {
	case code == http.StatusTooManyRequests, code == http.StatusServiceUnavailable && resp.Header.Get("Retry-After") != "":
		return true
	case code == http.StatusRequestTimeout, code == 999, code >= 500 && code < 600:
		// 999 is a non-standard status some edges return for upstream failures.
		return replayable
	}
	return false
}
