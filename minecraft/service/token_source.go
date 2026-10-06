package service

import (
	"context"
	"fmt"
	"sync"

	"github.com/df-mc/go-playfab/v2"
	"github.com/google/uuid"
)

// SessionTicketSource supplies PlayFab session tickets; [*playfab.Client] implements it.
type SessionTicketSource interface {
	SessionTicket(ctx context.Context) (string, error)
}

// TokenInvalidator discards a service token a service rejected before its expiry.
// Token sources that cache tokens implement it; the next ServiceToken call must not reuse rejected.
type TokenInvalidator interface {
	InvalidateServiceToken(rejected *Token)
}

// SessionIdentifier is implemented by token sources bound to one game session, so the requests
// they authorize name the same Session-Id.
type SessionIdentifier interface {
	SessionID() string
}

// TokenSource returns an implementation of TokenSource, which subsequently supplies the token
// by either newly requesting or refreshing an existing, cached token. The given [playfab.Client]
// will be used for logging into Bedrock Edition's network services with the user's PlayFab account.
func (e *AuthorizationEnvironment) TokenSource(client *playfab.Client, config TokenConfig) TokenSource {
	return e.ResumeTokenSource(client, config, nil)
}

// ResumeTokenSource returns a TokenSource like [AuthorizationEnvironment.TokenSource] that starts
// from a previously issued token, such as one restored from disk. It asks tickets for a session
// ticket only when that token must be renewed or replaced. The source implements [TokenInvalidator].
// Missing claims are decoded from the token's JWT; invalid persisted claims discard the token.
func (e *AuthorizationEnvironment) ResumeTokenSource(tickets SessionTicketSource, config TokenConfig, token *Token) TokenSource {
	defaultUserConfig(&config.User)
	defaultDeviceConfig(e, &config.Device)
	if config.SessionID == "" {
		config.SessionID = uuid.NewString()
	}

	if token != nil && token.Claims.PlayerMessagingID == uuid.Nil {
		// Claims are omitted from JSON. Rebuild them without changing the caller's token.
		restored := *token
		if err := decodeClaims(&restored, restored.now()); err != nil {
			token = nil
		} else {
			token = &restored
		}
	}

	return &tokenSource{
		tickets: tickets,
		env:     e,
		config:  config,
		token:   token,
	}
}

// tokenSource is an implementation of TokenSource that supplies tokens by
// reusing existing tokens whenever possible.
type tokenSource struct {
	tickets SessionTicketSource
	env     *AuthorizationEnvironment
	config  TokenConfig

	token *Token
	mu    sync.Mutex
}

// ServiceToken supplies a token by either re-using an already requested token, or
// requesting or renewing the existing token with a valid PlayFab session ticket.
func (s *tokenSource) ServiceToken(ctx context.Context) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != nil && s.token.Valid() {
		return s.token, nil
	}

	// PlayFab Client reuses the cached session ticket from last login if valid.
	// Otherwise, it refreshes the session ticket (approximately 24 hours after login).
	ticket, err := s.tickets.SessionTicket(ctx)
	if err != nil {
		return nil, fmt.Errorf("request session ticket: %w", err)
	}
	s.config.User.TokenType = TokenTypePlayFab
	s.config.User.Token = ticket

	// Renewal authenticates with the existing token, so it only works before the
	// token's hard expiry; otherwise, or on a rejected renewal, start fresh.
	if tokenRenewable(s.token) {
		if token, err := s.env.Renew(ctx, s.token, s.config.User); err == nil {
			s.token = token
			return s.token, nil
		}
	}

	token, err := s.env.Token(ctx, s.config)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	s.token = token
	return s.token, nil
}

// SessionID returns the Session-Id every request of this source sends.
func (s *tokenSource) SessionID() string { return s.config.SessionID }

// InvalidateServiceToken drops rejected if it is still cached, so the next call issues a new
// token instead of renewing one the service refused.
func (s *tokenSource) InvalidateServiceToken(rejected *Token) {
	if rejected == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != nil && s.token.AuthorizationHeader == rejected.AuthorizationHeader {
		s.token = nil
	}
}

// tokenRenewable reports whether tok can still authenticate a renewal request,
// i.e. it has not passed its hard expiry (ValidUntil).
func tokenRenewable(tok *Token) bool {
	return tok != nil && tok.AuthorizationHeader != "" && tok.now().Before(tok.ValidUntil)
}
