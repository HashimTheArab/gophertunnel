package authclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"sync/atomic"
	"time"
)

type RetryOptions struct {
	Attempts int           // how many times to send the request (default: DefaultAttempts)
	Factor   float64       // factor to multiply the delay by on each attempt (default: 2.0)
	MinDelay time.Duration // minimum delay (default: 500ms)
	MaxDelay time.Duration // Maximum delay (default: 8s)
}

// ErrNotSent wraps the error of a request that provably never left the client, so its effect cannot have happened.
var ErrNotSent = errors.New("request not sent")

// SendRequestWithRetries sends a request and retries on 429, 5xx and network errors. A request that may have
// reached the server is only sent again if it is safe to repeat. A retry delay that would end after ctx's
// deadline returns the last outcome instead of waiting. Errors wrap ErrNotSent only when no attempt can have
// reached the server.
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

	everSent := false // whether any attempt may have reached the server
	notSent := func(err error) error {
		if err != nil && !everSent {
			return fmt.Errorf("%w: %w", ErrNotSent, err)
		}
		return err
	}
	for i := 1; ; i++ {
		var tlsFailed atomic.Bool
		trace := &httptrace.ClientTrace{TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err != nil {
				tlsFailed.Store(true)
			}
		}}
		req := request.Clone(httptrace.WithClientTrace(ctx, trace))
		if request.Body != nil && request.GetBody != nil {
			body, err := request.GetBody()
			if err != nil {
				return nil, notSent(err)
			}
			req.Body = body
		}

		resp, err := c.Do(req)
		unsent := err != nil && (tlsFailed.Load() || dialFailed(err))
		everSent = everSent || !unsent
		var retryAfter time.Duration
		retry := false
		if err != nil {
			if ctx.Err() != nil {
				err = ctx.Err()
			} else {
				// Some proxies close the connection without a response, which often surfaces as EOF.
				_, netErr := errors.AsType[net.Error](err)
				retry = (netErr || errors.Is(err, io.EOF)) && (unsent || idempotent(request))
			}
		} else if retryableStatus(resp.StatusCode) {
			retry = true
			if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
				if seconds, parseErr := strconv.Atoi(resp.Header.Get("Retry-After")); parseErr == nil {
					retryAfter = time.Duration(seconds) * time.Second
				}
			}
		}
		if !retry || i >= opts.Attempts || !recreatable(request) {
			return resp, notSent(err)
		}

		delay := max(min(opts.MinDelay*time.Duration(math.Pow(opts.Factor, float64(i))), opts.MaxDelay), retryAfter)
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= delay {
			// Waiting would end after the deadline, so the last outcome is more useful than a deadline error.
			return resp, notSent(err)
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		select {
		case <-ctx.Done():
			return nil, notSent(ctx.Err())
		case <-time.After(delay):
		}
	}
}

// dialFailed reports whether err shows the connection was never made: a failed DNS lookup or dial.
func dialFailed(err error) bool {
	if _, ok := errors.AsType[*net.DNSError](err); ok {
		return true
	}
	op, ok := errors.AsType[*net.OpError](err)
	return ok && op.Op == "dial"
}

// retryableStatus reports whether a response status is worth retrying: 429, 408, 5xx, and the non-standard 999
// some edges return for upstream failures.
func retryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || code == http.StatusRequestTimeout || code == 999 || (code >= 500 && code < 600)
}

// recreatable reports whether req's body can be sent again.
func recreatable(req *http.Request) bool {
	return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
}

// idempotent reports whether sending req again cannot repeat its effect: an idempotent method or an idempotency
// key as recognised by net/http.
func idempotent(req *http.Request) bool {
	switch req.Method {
	case "", http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace, http.MethodPut, http.MethodDelete:
		return true
	}
	_, key := req.Header["Idempotency-Key"]
	_, xKey := req.Header["X-Idempotency-Key"]
	return key || xKey
}
