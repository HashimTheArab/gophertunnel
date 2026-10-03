// Package request sends the MCToken-authorized JSON requests shared by the Minecraft service clients.
package request

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/sandertv/gophertunnel/minecraft/auth/authclient"
	"github.com/sandertv/gophertunnel/minecraft/service"
	"github.com/sandertv/gophertunnel/minecraft/service/internal"
)

// MaxBody bounds a decoded response body.
const MaxBody = 8 << 20

// Options adjusts one request.
type Options struct {
	// Header holds extra request headers.
	Header http.Header
	// Retry is the transient-failure policy; a request that must be sent at most once sets Attempts to 1.
	Retry authclient.RetryOptions
}

// Response is the metadata of a successful answer.
type Response struct {
	StatusCode int
	Header     http.Header
}

// Do sends method to target with body encoded as JSON (nil sends none) and decodes the answer's
// {"result": ...} envelope into out (nil skips decoding). A non-2xx answer is a *service.ResponseError;
// a missing, oversized or malformed result is an error, never an empty success.
func Do(ctx context.Context, client *http.Client, src service.TokenSource, method string, target *url.URL, body, out any, opts Options) (*Response, error) {
	data, resp, err := Raw(ctx, client, src, method, target, body, opts)
	if err != nil {
		return nil, err
	}
	if out != nil {
		var envelope internal.Result[json.RawMessage]
		if err := json.Unmarshal(data, &envelope); err != nil {
			return nil, fmt.Errorf("decode response body: %w", err)
		}
		if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
			return nil, errors.New("minecraft/service: response has no result")
		}
		if err := json.Unmarshal(envelope.Data, out); err != nil {
			return nil, fmt.Errorf("decode result: %w", err)
		}
	}
	return resp, nil
}

// Raw sends the request like Do and returns the bounded body of a 2xx answer undecoded.
func Raw(ctx context.Context, client *http.Client, src service.TokenSource, method string, target *url.URL, body any, opts Options) ([]byte, *Response, error) {
	if client == nil {
		client = http.DefaultClient
	}
	var encoded []byte
	if body != nil {
		var err error
		if encoded, err = json.Marshal(body); err != nil {
			return nil, nil, fmt.Errorf("encode request body: %w", err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(encoded))
	if err != nil {
		return nil, nil, fmt.Errorf("make request: %w", err)
	}
	if body == nil {
		req.Body, req.GetBody, req.ContentLength = nil, nil, 0
	} else {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", internal.UserAgent)
	for name, values := range opts.Header {
		req.Header[name] = values
	}
	token, err := src.ServiceToken(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("request service token: %w", err)
	}
	token.SetAuthHeader(req)

	resp, err := authclient.SendRequestWithRetries(ctx, client, req, opts.Retry)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, nil, service.NewResponseError(resp)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read response body: %w", err)
	}
	if len(data) > MaxBody {
		return nil, nil, errors.New("minecraft/service: response body too large")
	}
	return data, &Response{StatusCode: resp.StatusCode, Header: resp.Header}, nil
}
