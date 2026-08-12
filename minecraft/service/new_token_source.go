package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/df-mc/go-playfab/v2"
	"github.com/df-mc/go-xsapi/v2"
	"github.com/sandertv/gophertunnel/minecraft/auth"
)

// TokenSourceConfig configures [NewTokenSource]. The zero value uses the
// default HTTP client and the default PlayFab and service token options.
type TokenSourceConfig struct {
	// HTTPClient is used for discovery, PlayFab login and Minecraft service
	// token requests. A client already stored on the context takes precedence.
	// If nil, http.DefaultClient is used.
	HTTPClient *http.Client
	// PlayFab configures the PlayFab client. When PlayFab.HTTPClient is nil,
	// HTTPClient is used.
	PlayFab playfab.ClientConfig
	// Token configures Minecraft service tokens issued by the discovered
	// authorization environment.
	Token TokenConfig
}

// ManagedTokenSource is a [TokenSource] that owns the PlayFab client used to
// refresh its credentials. Close must be called when the source is no longer
// needed to stop the PlayFab client's background work.
type ManagedTokenSource struct {
	TokenSource
	playFab *playfab.Client
}

// NewTokenSource constructs the standard Minecraft service token source by
// discovering the current authorization environment, logging in to PlayFab
// with Xbox and binding the resulting PlayFab client to that environment.
func NewTokenSource(ctx context.Context, xbox xsapi.TokenAndSignaturer, config TokenSourceConfig) (*ManagedTokenSource, error) {
	if xbox == nil {
		return nil, errors.New("minecraft/service: Xbox signer is nil")
	}

	ctx = auth.WithContextClient(ctx, config.HTTPClient)
	discovery, err := Default(ctx)
	if err != nil {
		return nil, fmt.Errorf("minecraft/service: discover service endpoints: %w", err)
	}
	env := new(AuthorizationEnvironment)
	if err := discovery.Environment(env); err != nil {
		return nil, fmt.Errorf("minecraft/service: resolve authorization environment: %w", err)
	}
	env.HTTPClient = auth.ContextClient(ctx)
	return env.NewTokenSource(ctx, xbox, config)
}

// NewTokenSource logs in to PlayFab with Xbox and constructs a managed token
// source bound to e. It is useful when the authorization environment has
// already been discovered for other operations.
func (e *AuthorizationEnvironment) NewTokenSource(ctx context.Context, xbox xsapi.TokenAndSignaturer, config TokenSourceConfig) (*ManagedTokenSource, error) {
	if xbox == nil {
		return nil, errors.New("minecraft/service: Xbox signer is nil")
	}
	ctx = auth.WithContextClient(ctx, config.HTTPClient)
	ctx = auth.WithContextClient(ctx, e.HTTPClient)
	// Bind the source to its own environment so callers may select different
	// clients concurrently without mutating a shared discovered environment.
	env := &AuthorizationEnvironment{
		ServiceURI:         e.ServiceURI,
		Issuer:             e.Issuer,
		PlayFabTitleID:     e.PlayFabTitleID,
		EduPlayFabTitleID:  e.EduPlayFabTitleID,
		HTTPClient:         auth.ContextClient(ctx),
		KeyRefreshInterval: e.KeyRefreshInterval,
	}
	playFabConfig := config.PlayFab
	if playFabConfig.HTTPClient == nil {
		playFabConfig.HTTPClient = env.HTTPClient
	}
	playFabClient, err := playfab.LoginWithXbox(ctx, env.PlayFabTitleID, xbox, playFabConfig)
	if err != nil {
		return nil, fmt.Errorf("minecraft/service: log in to PlayFab with Xbox: %w", err)
	}
	return &ManagedTokenSource{
		TokenSource: env.TokenSource(playFabClient, config.Token),
		playFab:     playFabClient,
	}, nil
}

// Close stops background work owned by the underlying PlayFab client.
func (s *ManagedTokenSource) Close() error {
	return s.playFab.Close()
}
