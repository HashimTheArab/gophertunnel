package minecraft

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/df-mc/go-playfab/v2"
	"github.com/df-mc/go-xsapi/v2"
	"github.com/df-mc/go-xsapi/v2/xal/nsal"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/service"
)

func (d Dialer) normalized() Dialer {
	if d.ErrorLog == nil {
		d.ErrorLog = slog.New(internal.DiscardHandler{})
	}
	d.ErrorLog = d.ErrorLog.With("src", "dialer")
	if d.Protocol == nil {
		d.Protocol = DefaultProtocol
	}
	if d.FlushRate == 0 {
		d.FlushRate = time.Second / 20
	}
	if d.HTTPClient == nil {
		d.HTTPClient = http.DefaultClient
	}

	return d
}

type dialAuthentication struct {
	ctx              context.Context
	release          func() error
	token            string
	identityProvider string
	verifier         *oidc.IDTokenVerifier
	identityData     login.IdentityData
}

func (d Dialer) authenticate(ctx context.Context, key *ecdsa.PrivateKey) (result dialAuthentication, err error) {
	result.ctx = ctx
	result.identityData = d.IdentityData
	var (
		token            string
		identityProvider string
		verifier         *oidc.IDTokenVerifier
	)
	if d.PlayFabClient != nil && d.TokenSource == nil && d.XBLClient == nil {
		return result, &net.OpError{Op: "dial", Net: "minecraft", Err: errors.New("PlayFabClient requires XBLClient or TokenSource for authenticated login")}
	}
	if d.TokenSource != nil || d.XBLClient != nil {
		ctx = auth.WithContextClient(ctx, d.HTTPClient)
		result.ctx = ctx
		e, err := authEnv(ctx)
		if err != nil {
			return result, &net.OpError{Op: "dial", Net: "minecraft", Err: fmt.Errorf("request authorization environment: %w", err)}
		}
		identityProvider = netherNetIdentityProvider(e.Issuer)
		verifier, err = e.VerifierContext(ctx)
		if err != nil {
			return result, &net.OpError{Op: "dial", Net: "minecraft", Err: fmt.Errorf("create OIDC verifier: %w", err)}
		}

		m, ok := d.TokenSource.(MultiplayerTokenSource)
		if !ok {
			var playFabSigner xsapi.TokenAndSignaturer
			if d.XBLClient != nil {
				playFabSigner = d.XBLClient
			} else {
				x, ok := d.TokenSource.(xsapi.TokenSource)
				if !ok {
					x = auth.ContextSession(ctx, d.TokenSource)
				}
				playFabSigner = nsal.NewResolver(x)
			}

			// If a MultiplayerTokenSource was not provided, log in to PlayFab
			// account and use a default implementation instead.
			if d.PlayFabClient == nil {
				client, err := playfab.LoginWithXbox(ctx, e.PlayFabTitleID, playFabSigner, playfab.ClientConfig{
					HTTPClient:    d.HTTPClient,
					CreateAccount: true,
				})
				if err != nil {
					return result, &net.OpError{Op: "dial", Net: "minecraft", Err: fmt.Errorf("login to playfab: %w", err)}
				}
				result.release = client.Close

				d.PlayFabClient = client
			}
			m = NewMultiplayerTokenSource(e, e.TokenSource(d.PlayFabClient, service.TokenConfig{}))
		}
		token, err = m.MultiplayerToken(ctx, &key.PublicKey)
		if err != nil {
			return result, &net.OpError{Op: "dial", Net: "minecraft", Err: err}
		}
		identityData, err := login.ParseTokenIdentityData(ctx, token, verifier)
		if err != nil {
			return result, &net.OpError{Op: "dial", Net: "minecraft", Err: err}
		}
		result.identityData = identityData
	}
	result.token, result.identityProvider, result.verifier = token, identityProvider, verifier
	return result, nil
}

func (a dialAuthentication) close() {
	if a.release != nil {
		_ = a.release()
	}
}

func (d Dialer) configureConn(conn *Conn, identity login.IdentityData) {
	conn.pool = serverPacketPool(conn.proto, d.LazyBlockActorData)
	conn.identityData = identity
	conn.clientData = d.ClientData
	conn.packetFunc = d.PacketFunc
	conn.acceptPacketHeader = d.AcceptPacketHeader
	conn.downloadResourcePack = d.DownloadResourcePack
	conn.resourcePackDownload = d.ResourcePackDownload.normalized()
	conn.resourcePackCache = d.ResourcePackCache
	conn.httpClient = d.HTTPClient
	conn.resourcePackProgress = d.ResourcePackProgress
	conn.relayStartup = d.RelayStartup
	conn.cacheEnabled = d.EnableClientCache
	conn.forwardClientCacheStatus = d.ForwardClientCacheStatus
	conn.disconnectOnInvalidPacket = d.DisconnectOnInvalidPackets
	conn.disconnectOnUnknownPacket = d.DisconnectOnUnknownPackets
	conn.maxDecompressedLen = d.MaxDecompressedLen
	conn.disablePacketHandling = d.DisablePacketHandling
	conn.batchReading = d.EnableBatchReading
	conn.SetPacketBatchFunc(d.PacketBatchFunc)
}
