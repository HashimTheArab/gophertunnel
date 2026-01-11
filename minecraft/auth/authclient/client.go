package authclient

import (
	"context"
	"errors"
	"math"
	"net"
	"net/http"
	"strconv"
	"time"
)

type RetryOptions struct {
	Attempts int           // how many times to send the request (default: 3)
	Factor   float64       // factor to multiply the delay by on each attempt (default: 2.0)
	MinDelay time.Duration // minimum delay (default: 500ms)
	MaxDelay time.Duration // Maximum delay (default: 8s)
}

// SendRequestWithRetries sends a request and retries on 429, 5xx and network errors.
func SendRequestWithRetries(ctx context.Context, c *http.Client, request *http.Request, r ...RetryOptions) (*http.Response, error) {
	var opts RetryOptions
	if len(r) > 0 {
		opts = r[0]
	}
	if opts.Attempts <= 0 {
		opts.Attempts = 3
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

	var resp *http.Response
	var err error
	var retryAfterDelay time.Duration

	for i := range opts.Attempts {
		if i > 0 {
			delay := min(opts.MinDelay*time.Duration(math.Pow(opts.Factor, float64(i))), opts.MaxDelay)

			// Use any retry-after delay from previous response
			if retryAfterDelay > 0 {
				delay = max(delay, retryAfterDelay)
				retryAfterDelay = 0 // Reset for next iteration
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		// Clone the request for each attempt to avoid issues with consumed request bodies
		req := request.Clone(request.Context())
		if request.Body != nil && request.GetBody != nil {
			req.Body, err = request.GetBody()
			if err != nil {
				return nil, err
			}
		}

		resp, err = c.Do(req)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return resp, err
			}
			var netErr net.Error
			if errors.As(err, &netErr) {
				continue
			}
			// Not a network error, so don't retry
			return resp, err
		}

		// Retry on 429, 408, and 5xx server errors
		if resp.StatusCode == http.StatusTooManyRequests ||
			resp.StatusCode == http.StatusRequestTimeout ||
			(resp.StatusCode >= 500 && resp.StatusCode < 600) {
			// Read Retry-After header before closing body
			if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
				if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
					if seconds, parseErr := strconv.Atoi(retryAfter); parseErr == nil {
						retryAfterDelay = time.Duration(seconds) * time.Second
					}
				}
			}
			// Always close the response body immediately
			resp.Body.Close()
			continue
		}

		// Success or a non-5xx error code.
		return resp, nil
	}

	// No more attempts, return last resp and error.
	return resp, err
}
