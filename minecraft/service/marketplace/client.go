// Package marketplace talks to the Minecraft Marketplace services as the signed-in player:
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

// EntitlementsEnvironment is the discovered inventory, balance and purchase service endpoint.
type EntitlementsEnvironment struct {
	internal.ServiceEnvironment
	// HTTPClient sends the requests; nil uses http.DefaultClient.
	HTTPClient *http.Client `json:"-"`
}

// ServiceName implements [service.Environment] and returns "entitlements".
func (*EntitlementsEnvironment) ServiceName() string { return "entitlements" }

// New returns a Client authorized by src, using both discovered service endpoints.
// Each request and its redirects stay on the origin of the service that owns it.
func (e *Environment) New(src service.TokenSource, entitlements *EntitlementsEnvironment) (*Client, error) {
	if e == nil || entitlements == nil {
		return nil, errors.New("service/marketplace: store and entitlements environments are required")
	}
	store, err := newServiceClient(e.ServiceName(), e.ServiceURI, e.HTTPClient, src)
	if err != nil {
		return nil, err
	}
	owned, err := newServiceClient(entitlements.ServiceName(), entitlements.ServiceURI, entitlements.HTTPClient, src)
	if err != nil {
		return nil, err
	}
	return &Client{store: store, entitlements: owned, sessionID: uuid.NewString()}, nil
}

// Client uses the store and entitlements services; it is safe for concurrent use.
type Client struct {
	store, entitlements *serviceClient
	sessionID           string
}

// SessionID is the Session-Id the client sends with its session config request.
func (c *Client) SessionID() string { return c.sessionID }

// serviceClient confines requests and redirects to one discovered service origin.
type serviceClient struct {
	base *url.URL
	http *http.Client
	src  service.TokenSource
}

// newServiceClient validates an endpoint and gives it an HTTP client restricted to that origin.
func newServiceClient(name string, u *url.URL, client *http.Client, src service.TokenSource) (*serviceClient, error) {
	if u == nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("service/marketplace: %s service URI must be an absolute https URL", name)
	}
	base := *u
	if client == nil {
		client = http.DefaultClient
	}
	scoped := *client
	next := scoped.CheckRedirect
	scoped.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if !sameOrigin(&base, req.URL) {
			return fmt.Errorf("service/marketplace: redirect leaves the %s origin", name)
		}
		if next != nil {
			return next(req, via)
		}
		if len(via) >= 10 {
			return errors.New("service/marketplace: stopped after 10 redirects")
		}
		return nil
	}
	return &serviceClient{base: &base, http: &scoped, src: src}, nil
}

// sameOrigin reports whether a target uses the service's scheme and host without user information.
func sameOrigin(base, u *url.URL) bool {
	return u.User == nil && strings.EqualFold(u.Scheme, base.Scheme) && strings.EqualFold(u.Host, base.Host)
}

// endpoint joins path onto the service base URI; path segments cannot change the origin.
func (c *serviceClient) endpoint(elem ...string) *url.URL {
	return c.base.JoinPath(elem...)
}

// do sends a request that may be retried on transient failures.
func (c *serviceClient) do(ctx context.Context, method string, target *url.URL, body, out any, header http.Header) (*request.Response, error) {
	if !sameOrigin(c.base, target) {
		return nil, fmt.Errorf("service/marketplace: %s is off the service origin", target.Redacted())
	}
	return request.Do(ctx, c.http, c.src, method, target, body, out, request.Options{Header: header})
}

// raw sends a retryable request and returns the whole body; for answers whose envelope carries
// members beside result.
func (c *serviceClient) raw(ctx context.Context, method string, target *url.URL, body any) ([]byte, *request.Response, error) {
	if !sameOrigin(c.base, target) {
		return nil, nil, fmt.Errorf("service/marketplace: %s is off the service origin", target.Redacted())
	}
	return request.Raw(ctx, c.http, c.src, method, target, body, request.Options{})
}
