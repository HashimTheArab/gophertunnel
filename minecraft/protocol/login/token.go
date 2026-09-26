package login

import (
	"context"
	"crypto/ecdsa"
	"crypto/md5"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// tokenClaims holds the identity and public key in a multiplayer token.
type tokenClaims struct {
	jwt.Claims

	IdentityProviderType string `json:"ipt"`
	PlayFabID            string `json:"mid"`
	PlayFabTitleID       string `json:"tid"`
	ClientPublicKey      string `json:"cpk"`
	XUID                 string `json:"xid"`
	DisplayName          string `json:"xname"`
	NintendoID           string `json:"nid"`
	NintendoName         string `json:"nname"`
	PlayStationID        string `json:"pid"`
	PlayStationName      string `json:"pname"`
	Identity             string `json:"leguuid,omitempty"`
}

// parseMultiplayerToken verifies the selected token type and extracts the key that signs client data.
// Service tokens may be read without verification when the caller disables authentication. Only a
// verified service token can select the trusted-host name rules.
func parseMultiplayerToken(raw string, verifier *oidc.IDTokenVerifier, selfSigned bool, now time.Time) (tokenClaims, *ecdsa.PublicKey, bool, error) {
	var claims tokenClaims
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES384, jose.RS256})
	if err != nil {
		return claims, nil, false, fmt.Errorf("parse multiplayer token: %w", err)
	}
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return claims, nil, false, fmt.Errorf("parse multiplayer token claims: %w", err)
	}
	key := new(ecdsa.PublicKey)
	if err := ParsePublicKey(claims.ClientPublicKey, key); err != nil {
		return claims, nil, false, fmt.Errorf("parse cpk: %w", err)
	}
	if selfSigned {
		if err := tok.Claims(key, &claims); err != nil {
			return claims, nil, false, fmt.Errorf("verify self-signed token: %w", err)
		}
		if claims.Expiry == nil || now.Unix() > int64(*claims.Expiry) {
			return claims, nil, false, fmt.Errorf("self-signed token has expired")
		}
		return claims, key, false, nil
	}
	if verifier == nil {
		return claims, key, false, nil
	}
	idt, err := verifier.Verify(context.Background(), raw)
	if err != nil {
		return claims, nil, false, fmt.Errorf("verify ID token: %w", err)
	}
	if err := idt.Claims(&claims); err != nil {
		return claims, nil, false, fmt.Errorf("parse ID token: %w", err)
	}
	if err := claims.Validate(jwt.Expected{Time: now}); err != nil {
		return claims, nil, false, fmt.Errorf("validate ID token: %w", err)
	}
	return claims, key, tok.Headers[0].KeyID == "host", nil
}

// identityData selects the platform identity or resolves the client's fallback UUID and name.
func (tc tokenClaims) identityData(data ClientData, selfSigned, trustedHost bool) (IdentityData, error) {
	if selfSigned {
		// A self-signed token cannot establish an account ID, even if it includes one in its claims.
		tc.XUID, tc.NintendoID, tc.PlayStationID, tc.PlayFabID, tc.PlayFabTitleID = "", "", "", "", ""
		trustedHost = false
	}
	id := parseIdentityUUID(tc.Identity)
	switch {
	case tc.XUID != "":
		id = identityFromID("xuid", tc.XUID)
	case tc.PlayStationID != "":
		id = identityFromID("psn", tc.PlayStationID)
	case tc.NintendoID != "":
		id = identityFromID("nsa", tc.NintendoID)
	}
	if selfSigned && id == uuid.Nil {
		id = parseIdentityUUID(data.SelfSignedID)
	}
	var name string
	switch {
	case tc.XUID != "" && tc.DisplayName != "":
		name = tc.DisplayName
	case data.DeviceOS == protocol.DeviceNX && tc.NintendoID != "" && tc.NintendoName != "":
		name = tc.NintendoName
	case data.DeviceOS == protocol.DeviceOrbis && tc.PlayStationID != "" && tc.PlayStationName != "":
		name = tc.PlayStationName
	default:
		var err error
		name, err = fallbackDisplayName(data.ThirdPartyName, data.DeviceOS, trustedHost)
		if err != nil {
			return IdentityData{}, err
		}
	}
	return IdentityData{
		XUID:           tc.XUID,
		Identity:       id.String(),
		DisplayName:    name,
		PlayFabID:      tc.PlayFabID,
		PlayFabTitleID: tc.PlayFabTitleID,
	}, nil
}

// parseIdentityUUID accepts the compact or hyphenated UUID formats used by the game. Invalid text
// resolves to the zero UUID so that an offline login can fall back to SelfSignedId.
func parseIdentityUUID(value string) uuid.UUID {
	if len(value) != 32 && len(value) != 36 {
		return uuid.Nil
	}
	id, err := uuid.Parse(value)
	if err != nil {
		return uuid.Nil
	}
	return id
}

// identityFromID derives a version 3 UUID from a platform's account ID and namespace.
func identityFromID(platform, id string) uuid.UUID {
	sum := md5.Sum([]byte("pocket-auth-1-" + platform + ":" + id))
	sum[6] = (sum[6] & 0x0f) | 0x30
	sum[8] = (sum[8] & 0x3f) | 0x80
	return uuid.UUID(sum)
}
