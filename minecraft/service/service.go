package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/df-mc/go-playfab"
	"github.com/df-mc/go-playfab/title"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

type Transport struct {
	IdentityProvider playfab.IdentityProvider
	Base             http.RoundTripper

	mu    sync.Mutex
	env   *AuthorizationEnvironment
	token *Token
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.IdentityProvider == nil {
		return nil, errors.New("minecraft/service: Transport: IdentityProvider is nil")
	}

	tok, err := t.serviceToken(req.Context())
	if err != nil {
		return nil, err
	}

	req2 := cloneRequest(req)
	tok.SetAuthHeader(req2)
	return t.base().RoundTrip(req2)
}

func (t *Transport) serviceToken(ctx context.Context) (*Token, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.token != nil && t.token.Valid() {
		return t.token, nil
	}

	if t.env == nil {
		discovery, err := Discover(ctx, ApplicationTypeMinecraftPE, protocol.CurrentVersion)
		if err != nil {
			return nil, fmt.Errorf("minecraft/service: discover: %w", err)
		}
		env := new(AuthorizationEnvironment)
		if err := discovery.Environment(env); err != nil {
			return nil, fmt.Errorf("minecraft/service: environment(auth): %w", err)
		}

		// IMPORTANT: Avoid recursion if the caller’s http.Client.Transport is this Transport.
		// Use the Base round tripper for auth-service calls.
		env.HTTPClient = &http.Client{Transport: t.base()}
		t.env = env
	}

	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
	}

	identity, err := t.IdentityProvider.Login(playfab.LoginConfig{
		Title:         title.Title(t.env.PlayFabTitleID),
		CreateAccount: true,
	})
	if err != nil {
		return nil, fmt.Errorf("minecraft/service: login playfab: %w", err)
	}

	user := UserConfig{
		TokenType: TokenTypePlayFab,
		Token:     identity.SessionTicket,
	}

	if t.token == nil {
		t.token, err = t.env.Token(ctx, TokenConfig{User: user})
		if err != nil {
			return nil, fmt.Errorf("minecraft/service: request token: %w", err)
		}
	} else if !t.token.Valid() {
		t.token, err = t.env.Renew(ctx, t.token, user)
		if err != nil {
			return nil, fmt.Errorf("minecraft/service: renew token: %w", err)
		}
	}

	return t.token, nil
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

// cloneRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
func cloneRequest(r *http.Request) *http.Request {
	r2 := new(http.Request)
	*r2 = *r
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}
	return r2
}
