package authclient

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

// callTransport supplies HTTP responses without making network connections.
type callTransport func(*http.Request) (*http.Response, error)

// RoundTrip runs the test's HTTP handler.
func (f callTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// preparePost creates a replayable POST so tests can check retries preserve its body.
func preparePost(ctx context.Context) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, http.MethodPost, "https://service.test", strings.NewReader("payload"))
}

// okResponse returns an empty successful response.
func okResponse() *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}
}

// timeoutError is a network timeout, as returned when a client's own Timeout expires.
type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// slowBody yields one byte after delay, modelling a slow but healthy response stream.
type slowBody struct {
	ctx   context.Context
	delay time.Duration
	done  bool
}

func (b *slowBody) Read(p []byte) (int, error) {
	if b.done {
		return 0, io.EOF
	}
	select {
	case <-time.After(b.delay):
	case <-b.ctx.Done():
		return 0, b.ctx.Err()
	}
	b.done = true
	return copy(p, "x"), nil
}

func (*slowBody) Close() error { return nil }

// A slow response body is read in full within the call's deadline.
func TestCallDoesNotCutOffSlowBodies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &http.Client{Transport: callTransport(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: &slowBody{ctx: req.Context(), delay: 15 * time.Second}}, nil
		})}
		resp, err := Call(context.Background(), client, preparePost, CallOptions{})
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if _, err := io.ReadAll(resp.Body); err != nil {
			t.Fatalf("slow body cut off: %v", err)
		}
	})
}

// A streamed call leaves its body bounded only by the caller's context.
func TestCallStreamLeavesBodyToContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &http.Client{Transport: callTransport(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: &slowBody{ctx: req.Context(), delay: 2 * DefaultCallTimeout}}, nil
		})}
		resp, err := Call(context.Background(), client, preparePost, CallOptions{Stream: true})
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if _, err := io.ReadAll(resp.Body); err != nil {
			t.Fatalf("streamed body cut off: %v", err)
		}
	})
}

// The call deadline covers preparing the request and reading the response body.
func TestCallDeadlineBoundsPreparationAndBody(t *testing.T) {
	for _, timeout := range []time.Duration{0, time.Second} {
		want := timeout
		if want == 0 {
			want = DefaultCallTimeout
		}
		synctest.Test(t, func(t *testing.T) {
			started := time.Now()
			_, err := Call(context.Background(), nil, func(ctx context.Context) (*http.Request, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			}, CallOptions{Timeout: timeout})
			if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) != want {
				t.Fatalf("prepare: err = %v, elapsed = %v, want %v", err, time.Since(started), want)
			}
		})
		synctest.Test(t, func(t *testing.T) {
			client := &http.Client{Transport: callTransport(func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: &slowBody{ctx: req.Context(), delay: 2 * DefaultCallTimeout}}, nil
			})}
			started := time.Now()
			resp, err := Call(context.Background(), client, preparePost, CallOptions{Timeout: timeout})
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if _, err := io.ReadAll(resp.Body); !errors.Is(err, context.DeadlineExceeded) || time.Since(started) != want {
				t.Fatalf("body: err = %v, elapsed = %v, want %v", err, time.Since(started), want)
			}
		})
	}
}

// A caller's own client timeout is used as it is.
func TestCallKeepsCallerClientTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &http.Client{Timeout: 30 * time.Second, Transport: callTransport(func(req *http.Request) (*http.Response, error) {
			select {
			case <-time.After(20 * time.Second):
				return okResponse(), nil
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}
		})}
		resp, err := Call(context.Background(), client, preparePost, CallOptions{})
		if err != nil {
			t.Fatalf("caller timeout shortened: %v", err)
		}
		resp.Body.Close()
		if client.Timeout != 30*time.Second {
			t.Fatalf("caller timeout changed to %v", client.Timeout)
		}
	})
}

func TestCallReleasesContextOnClose(t *testing.T) {
	var requestCtx context.Context
	client := &http.Client{Transport: callTransport(func(req *http.Request) (*http.Response, error) {
		requestCtx = req.Context()
		return okResponse(), nil
	})}
	resp, err := Call(context.Background(), client, preparePost, CallOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if requestCtx.Err() != nil {
		t.Fatal("request context was cancelled before the body was closed")
	}
	resp.Body.Close()
	if !errors.Is(requestCtx.Err(), context.Canceled) {
		t.Fatalf("context after closing body = %v", requestCtx.Err())
	}
}

func TestCallRetriesPreserveBodyAndPolicy(t *testing.T) {
	for _, test := range []struct {
		status   int
		attempts int
		want     int
	}{
		{status: http.StatusUnauthorized, want: 1},
		{status: http.StatusServiceUnavailable, want: DefaultAttempts},
		{status: http.StatusServiceUnavailable, attempts: 1, want: 1},
		{status: http.StatusServiceUnavailable, attempts: 4, want: 4},
	} {
		synctest.Test(t, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: callTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				if body, err := io.ReadAll(req.Body); err != nil || string(body) != "payload" {
					t.Fatalf("body = %q, err = %v", body, err)
				}
				resp := okResponse()
				resp.StatusCode = test.status
				return resp, nil
			})}
			resp, err := Call(context.Background(), client, preparePost, CallOptions{Retry: RetryOptions{Attempts: test.attempts}})
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if calls != test.want || resp.StatusCode != test.status {
				t.Fatalf("calls = %d, want %d; status = %d", calls, test.want, resp.StatusCode)
			}
		})
	}
}

// A failed attempt is resent only if it provably never left the client or repeating it cannot repeat its effect.
func TestCallResendsOnlyUnsentOrReplayableRequests(t *testing.T) {
	reset := &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
	dialTimeout := &net.OpError{Op: "dial", Net: "tcp", Err: timeoutError{}}
	for _, test := range []struct {
		name      string
		method    string
		header    string
		noGetBody bool
		tlsFailed bool
		err       error
		unsent    bool
		want      int
	}{
		{name: "post dial timeout", method: http.MethodPost, err: dialTimeout, unsent: true, want: DefaultAttempts},
		{name: "post failed TLS handshake", method: http.MethodPost, tlsFailed: true, err: timeoutError{}, unsent: true, want: DefaultAttempts},
		{name: "post timeout without evidence", method: http.MethodPost, err: timeoutError{}, want: 1},
		{name: "post reset", method: http.MethodPost, err: reset, want: 1},
		{name: "post with idempotency key", method: http.MethodPost, header: "Idempotency-Key", err: reset, want: DefaultAttempts},
		{name: "get reset", method: http.MethodGet, err: reset, want: DefaultAttempts},
		{name: "put without GetBody", method: http.MethodPut, noGetBody: true, err: reset, want: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				calls := 0
				client := &http.Client{Transport: callTransport(func(req *http.Request) (*http.Response, error) {
					calls++
					if trace := httptrace.ContextClientTrace(req.Context()); test.tlsFailed && trace != nil {
						trace.TLSHandshakeDone(tls.ConnectionState{}, errors.New("handshake failed"))
					}
					return nil, test.err
				})}
				_, err := Call(context.Background(), client, func(ctx context.Context) (*http.Request, error) {
					req, err := http.NewRequestWithContext(ctx, test.method, "https://service.test", strings.NewReader("payload"))
					if err == nil && test.header != "" {
						req.Header.Set(test.header, "key")
					}
					if err == nil && test.noGetBody {
						req.Body, req.GetBody = io.NopCloser(strings.NewReader("payload")), nil
					}
					return req, err
				}, CallOptions{})
				if err == nil || calls != test.want {
					t.Fatalf("err = %v, calls = %d, want %d", err, calls, test.want)
				}
				if errors.Is(err, ErrNotSent) != test.unsent {
					t.Fatalf("errors.Is(err, ErrNotSent) = %v, want %v", !test.unsent, test.unsent)
				}
			})
		})
	}
}

// A Retry-After wait that would end after the call's deadline returns that response instead of a deadline error.
func TestCallReturnsResponseWhenRetryAfterOutlastsDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		client := &http.Client{Transport: callTransport(func(*http.Request) (*http.Response, error) {
			calls++
			resp := &http.Response{StatusCode: http.StatusServiceUnavailable, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("busy"))}
			resp.Header.Set("Retry-After", "60")
			return resp, nil
		})}
		start := time.Now()
		resp, err := Call(context.Background(), client, preparePost, CallOptions{})
		if err != nil {
			t.Fatalf("err = %v, want the 503 response", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusServiceUnavailable || string(body) != "busy" || calls != 1 || time.Since(start) != 0 {
			t.Fatalf("status = %d, body = %q, calls = %d, waited %v", resp.StatusCode, body, calls, time.Since(start))
		}
	})
}

// A streamed call still bounds preparing the request, which includes fetching its token.
func TestCallStreamBoundsPreparation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, err := Call(context.Background(), http.DefaultClient, func(ctx context.Context) (*http.Request, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}, CallOptions{Stream: true})
		if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrNotSent) {
			t.Fatalf("err = %v, want an unsent deadline error", err)
		}
	})
}

func TestCallHonorsCancellation(t *testing.T) {
	for _, alreadyCancelled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		client := &http.Client{Transport: callTransport(func(req *http.Request) (*http.Response, error) {
			calls++
			cancel()
			return nil, req.Context().Err()
		})}
		if alreadyCancelled {
			cancel()
		}
		_, err := Call(ctx, client, preparePost, CallOptions{})
		cancel()
		want := 1
		if alreadyCancelled {
			want = 0
		}
		if !errors.Is(err, context.Canceled) || calls != want {
			t.Fatalf("err = %v, calls = %d, want %d", err, calls, want)
		}
	}
}

// A request whose redirect target cannot be dialled already reached the server that redirected it.
func TestCallTreatsFailedRedirectAsSent(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: callTransport(func(req *http.Request) (*http.Response, error) {
		if calls++; calls == 1 {
			return &http.Response{StatusCode: http.StatusSeeOther, Header: http.Header{"Location": {"https://other.test/"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("refused")}
	})}
	_, err := Call(context.Background(), client, preparePost, CallOptions{Retry: RetryOptions{Attempts: 1}})
	if err == nil || errors.Is(err, ErrNotSent) || calls != 2 {
		t.Fatalf("err = %v, calls = %d, want a sent error after the redirect", err, calls)
	}
}
