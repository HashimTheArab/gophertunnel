package xal

import (
	"context"
	"fmt"
	"sync"

	"github.com/df-mc/go-xsapi"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"golang.org/x/oauth2"
)

func RefreshTokenSource(ctx context.Context, underlying oauth2.TokenSource, relyingParty string) xsapi.TokenSource {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = context.WithoutCancel(ctx)
	return &refreshTokenSource{
		underlying:   underlying,
		relyingParty: relyingParty,
		ctx:          ctx,
	}
}

type refreshTokenSource struct {
	underlying oauth2.TokenSource

	relyingParty string

	t   *oauth2.Token
	x   *auth.XBLToken
	ctx context.Context
	mu  sync.Mutex
}

func (r *refreshTokenSource) Token() (_ xsapi.Token, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Return the cached XBL token if it is valid.
	if r.x != nil && r.x.Valid() {
		return r.x, nil
	}

	// Request a new underlying token if it is not valid.
	if r.t == nil || !r.t.Valid() {
		r.t, err = r.underlying.Token()
		if err != nil {
			return nil, fmt.Errorf("request underlying token: %w", err)
		}
	}

	// Request a new XBL token using the underlying token.
	r.x, err = auth.RequestXBLToken(r.ctx, r.t, r.relyingParty)
	if err != nil {
		return nil, fmt.Errorf("request xbox live token: %w", err)
	}

	return r.x, nil
}
