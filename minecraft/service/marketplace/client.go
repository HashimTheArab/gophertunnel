// Package marketplace talks to the Minecraft Marketplace store service as the signed-in player:
// session configuration, layout pages, balances, inventory and Minecoin purchases.
package marketplace

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/service"
	"github.com/sandertv/gophertunnel/minecraft/service/internal"
	"github.com/sandertv/gophertunnel/minecraft/service/internal/request"
)

// Environment is the discovered store service endpoint.
type Environment struct {
	internal.ServiceEnvironment
	// HTTPClient sends the requests; nil uses http.DefaultClient.
	HTTPClient *http.Client `json:"-"`
}

// ServiceName implements [service.Environment] and returns "store".
func (*Environment) ServiceName() string { return "store" }

// New returns a Client authorized by src. Every request stays on the environment's origin.
func (e *Environment) New(src service.TokenSource) (*Client, error) {
	u := e.ServiceURI
	if u == nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, errors.New("service/marketplace: store service URI must be an absolute https URL")
	}
	client := e.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	// A redirect off the store origin must not carry the service token.
	scoped := *client
	next := scoped.CheckRedirect
	scoped.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if !sameOrigin(u, req.URL) {
			return errors.New("service/marketplace: redirect leaves the store origin")
		}
		if next != nil {
			return next(req, via)
		}
		if len(via) >= 10 {
			return errors.New("service/marketplace: stopped after 10 redirects")
		}
		return nil
	}
	return &Client{base: u, http: &scoped, src: src, sessionID: uuid.NewString()}, nil
}

// Client is a store service client; it is safe for concurrent use.
type Client struct {
	base      *url.URL
	http      *http.Client
	src       service.TokenSource
	sessionID string
}

// SessionID is the Session-Id the client sends with its session config request.
func (c *Client) SessionID() string { return c.sessionID }

func sameOrigin(base, u *url.URL) bool {
	return u.User == nil && strings.EqualFold(u.Scheme, base.Scheme) && strings.EqualFold(u.Host, base.Host)
}

// endpoint joins path onto the store base URI; path segments cannot change the origin.
func (c *Client) endpoint(elem ...string) *url.URL {
	return c.base.JoinPath(elem...)
}

// do sends a request that may be retried on transient failures.
func (c *Client) do(ctx context.Context, method string, target *url.URL, body, out any, header http.Header) (*request.Response, error) {
	if !sameOrigin(c.base, target) {
		return nil, fmt.Errorf("service/marketplace: %s is off the store origin", target.Redacted())
	}
	return request.Do(ctx, c.http, c.src, method, target, body, out, request.Options{Header: header})
}

// raw sends a retryable request and returns the whole body; for answers whose envelope carries
// members beside result.
func (c *Client) raw(ctx context.Context, method string, target *url.URL, body any) ([]byte, *request.Response, error) {
	if !sameOrigin(c.base, target) {
		return nil, nil, fmt.Errorf("service/marketplace: %s is off the store origin", target.Redacted())
	}
	return request.Raw(ctx, c.http, c.src, method, target, body, request.Options{})
}
