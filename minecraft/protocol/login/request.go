package login

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// chain holds a chain with claims, each with their own headers, payloads and signatures. Each claim holds
// a public key used to verify other claims.
type chain []string

type certificate struct {
	Chain chain `json:"chain"`
}

// request is the outer encapsulation of the request. It holds a chain and a ClientData object.
type request struct {
	// Certificate holds the client certificate chain. The chain holds several claims that the server may verify in order to
	// make sure that the client is logged into XBOX Live.
	Certificate certificate `json:"Certificate"`
	// AuthenticationType is the authentication type of the request.
	AuthenticationType uint8 `json:"AuthenticationType"`
	// Token holds the multiplayer token, issued by the authentication service or self-signed for offline play.
	Token string `json:"Token"`
	// RawToken holds the raw token that follows the JWT chain, holding the ClientData.
	RawToken string `json:"-"`
	// Legacy specifies whether to use the legacy format of the request or not.
	Legacy bool `json:"-"`
}

func (r *request) MarshalJSON() ([]byte, error) {
	if r.Legacy {
		return json.Marshal(r.Certificate)
	}

	cert, err := json.Marshal(r.Certificate)
	if err != nil {
		return nil, err
	}

	type Alias request
	return json.Marshal(&struct {
		Certificate string `json:"Certificate"`
		Alias
	}{
		Certificate: string(cert),
		Alias:       (Alias)(*r),
	})
}

func init() {
	//noinspection SpellCheckingInspection
	const mojangPublicKey = `MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAECRXueJeTDqNRRgJi/vlRufByu/2G0i2Ebt6YMar5QX/R0DIIyrJMcUpruK4QveTfJSTp3Shlq4Gk34cD/4GUWwkv0DVuzeuB+tXija7HBxii03NHDbPAD0AKnLr2wdAp`

	data, _ := base64.StdEncoding.DecodeString(mojangPublicKey)
	publicKey, _ := x509.ParsePKIXPublicKey(data)
	mojangKey = publicKey.(*ecdsa.PublicKey)
}

// mojangKey holds the parsed Mojang ecdsa.PublicKey.
var mojangKey = new(ecdsa.PublicKey)

// AuthResult is returned by a call to Parse. It holds the ecdsa.PublicKey of the client and a bool that
// indicates if the player was logged in with XBOX Live.
type AuthResult struct {
	PublicKey             *ecdsa.PublicKey
	XBOXLiveAuthenticated bool
}

// Parse returns the resolved identity, client data and authentication result for a login request.
// A nil verifier reads service tokens without verification; check AuthResult before trusting the identity.
func Parse(request []byte, verifier *oidc.IDTokenVerifier) (IdentityData, ClientData, AuthResult, error) {
	var (
		iData IdentityData
		cData ClientData
		res   AuthResult
		key   *ecdsa.PublicKey
	)
	req, err := parseLoginRequest(request)
	if err != nil {
		return iData, cData, res, fmt.Errorf("parse login request: %w", err)
	}

	var (
		authenticated bool
		claims        tokenClaims
		trustedHost   bool
		t             = time.Now()
	)
	selfSigned := req.AuthenticationType == 2
	if req.Token != "" {
		claims, key, trustedHost, err = parseMultiplayerToken(req.Token, verifier, selfSigned, t)
		if err != nil {
			return iData, cData, res, err
		}
	} else {
		iData, key, authenticated, err = parseLegacyChain(req.Certificate.Chain, t)
		if err != nil {
			return iData, cData, res, err
		}
	}

	clientToken, err := jwt.ParseSigned(req.RawToken, []jose.SignatureAlgorithm{jose.ES384})
	if err != nil {
		return iData, cData, res, fmt.Errorf("parse client data: %w", err)
	}
	// Client data cannot rotate the key established by the login token or certificate chain.
	if err := clientToken.Claims(key, &cData); err != nil {
		return iData, cData, res, fmt.Errorf("verify client data: %w", err)
	}
	if strings.Count(cData.ServerAddress, ":") > 1 && cData.ServerAddress[0] != '[' {
		// IPv6: We can't net.ResolveUDPAddr this directly, because Mojang does
		// not always put [] around the IP if it isn't added by the player in
		// the External Server adding screen. We'll have to do this manually:
		ind := strings.LastIndex(cData.ServerAddress, ":")
		cData.ServerAddress = "[" + cData.ServerAddress[:ind] + "]" + cData.ServerAddress[ind:]
	}
	if err := cData.Validate(); err != nil {
		return iData, cData, res, fmt.Errorf("validate client data: %w", err)
	}
	if req.Token != "" {
		iData, err = claims.identityData(cData, selfSigned, trustedHost)
		if err != nil {
			return iData, cData, res, fmt.Errorf("resolve identity data: %w", err)
		}
		authenticated = !selfSigned && verifier != nil && iData.XUID != ""
		// Multiplayer tokens do not carry the legacy Xbox title ID. Use it only from a verified chain
		// that belongs to the same Xbox account.
		if authenticated && len(req.Certificate.Chain) > 0 {
			if legacyID, _, legacyAuthed, err := parseLegacyChain(req.Certificate.Chain, t); err == nil && legacyAuthed && legacyID.XUID == iData.XUID {
				iData.TitleID = legacyID.TitleID
			}
		}
	} else if !authenticated {
		// Legacy offline logins carry their name in extraData, not ThirdPartyName.
		iData.DisplayName, err = fallbackDisplayName(iData.DisplayName, cData.DeviceOS, false)
		if err != nil {
			return iData, cData, res, fmt.Errorf("resolve legacy display name: %w", err)
		}
	}
	if err := iData.Validate(); err != nil {
		return iData, cData, res, fmt.Errorf("validate identity data: %w", err)
	}
	return iData, cData, AuthResult{PublicKey: key, XBOXLiveAuthenticated: authenticated}, nil
}

// parseLegacyChain verifies the legacy Mojang chain and returns IdentityData from extraData,
// the public key used for verification (and for client data), and a bool indicating if the chain was
// authenticated by Xbox Live.
func parseLegacyChain(chain []string, now time.Time) (IdentityData, *ecdsa.PublicKey, bool, error) {
	if len(chain) == 0 {
		return IdentityData{}, nil, false, fmt.Errorf("decode chain: no elements")
	}
	key := &ecdsa.PublicKey{}
	tok, err := jwt.ParseSigned(chain[0], []jose.SignatureAlgorithm{jose.ES384})
	if err != nil {
		return IdentityData{}, nil, false, fmt.Errorf("parse token 0: %w", err)
	}

	// The first token holds the client's public key in the x5u (it's self signed).
	//lint:ignore S1005 Double assignment is done explicitly to prevent panics.
	raw, _ := tok.Headers[0].ExtraHeaders["x5u"]
	if err := parseAsKey(raw, key); err != nil {
		return IdentityData{}, nil, false, fmt.Errorf("parse x5u: %w", err)
	}

	var (
		identityClaims identityClaims
		authenticated  bool
	)
	iss := "Mojang"

	switch len(chain) {
	case 1:
		// Player was not authenticated with XBOX Live, meaning the one token in here is self-signed.
		if err := parseFullClaim(chain[0], key, &identityClaims); err != nil {
			return IdentityData{}, nil, false, err
		}
		if err := identityClaims.Validate(jwt.Expected{Time: now}); err != nil {
			return IdentityData{}, nil, false, fmt.Errorf("validate token 0: %w", err)
		}
	case 3:
		// Player was (or should be) authenticated with XBOX Live, meaning the chain is exactly 3 tokens long.
		var c jwt.Claims
		if err := parseFullClaim(chain[0], key, &c); err != nil {
			return IdentityData{}, nil, false, fmt.Errorf("parse token 0: %w", err)
		}
		if err := c.Validate(jwt.Expected{Time: now}); err != nil {
			return IdentityData{}, nil, false, fmt.Errorf("validate token 0: %w", err)
		}
		authenticated = bytes.Equal(key.X.Bytes(), mojangKey.X.Bytes()) && bytes.Equal(key.Y.Bytes(), mojangKey.Y.Bytes())

		if err := parseFullClaim(chain[1], key, &c); err != nil {
			return IdentityData{}, nil, false, fmt.Errorf("parse token 1: %w", err)
		}
		if err := c.Validate(jwt.Expected{Time: now, Issuer: iss}); err != nil {
			return IdentityData{}, nil, false, fmt.Errorf("validate token 1: %w", err)
		}
		if err := parseFullClaim(chain[2], key, &identityClaims); err != nil {
			return IdentityData{}, nil, false, fmt.Errorf("parse token 2: %w", err)
		}
		if err := identityClaims.Validate(jwt.Expected{Time: now, Issuer: iss}); err != nil {
			return IdentityData{}, nil, false, fmt.Errorf("validate token 2: %w", err)
		}
		if authenticated != (identityClaims.ExtraData.XUID != "") {
			return IdentityData{}, nil, false, fmt.Errorf("identity data must have an XUID when logged into XBOX Live only")
		}
	default:
		return IdentityData{}, nil, false, fmt.Errorf("unexpected login chain length %v", len(chain))
	}
	return identityClaims.ExtraData, key, authenticated, nil
}

// parseLoginRequest parses the structure of a login request from the data passed and returns it.
func parseLoginRequest(requestData []byte) (*request, error) {
	buf := bytes.NewBuffer(requestData)
	var chainLength int32
	if err := binary.Read(buf, binary.LittleEndian, &chainLength); err != nil {
		return nil, fmt.Errorf("read chain length: %w", err)
	}
	if chainLength <= 0 {
		return nil, fmt.Errorf("invalid chain length: %d", chainLength)
	}
	chainData := buf.Next(int(chainLength))

	r := struct {
		request
		Certificate string `json:"Certificate"`
		Chain       chain  `json:"chain"`
	}{}
	if err := json.Unmarshal(chainData, &r); err != nil {
		return nil, fmt.Errorf("decode chain data: %w", err)
	}

	if r.Certificate != "" {
		if err := json.Unmarshal([]byte(r.Certificate), &r.request.Certificate); err != nil {
			return nil, fmt.Errorf("decode certificate: %w", err)
		}
	} else {
		r.request.Certificate.Chain = r.Chain
	}

	// Then check if the authentication type is guest mode.
	if r.AuthenticationType == 1 {
		return nil, fmt.Errorf("guest authentication is not supported")
	}

	var rawLength int32
	if err := binary.Read(buf, binary.LittleEndian, &rawLength); err != nil {
		return nil, fmt.Errorf("read raw token length: %w", err)
	}
	r.request.RawToken = string(buf.Next(int(rawLength)))
	if n := buf.Len(); n != 0 {
		return nil, fmt.Errorf("%d unread bytes", n)
	}
	return &r.request, nil
}

// parseFullClaim parses and verifies a full claim using the ecdsa.PublicKey passed. The key passed is updated
// if the claim holds an identityPublicKey field.
// The value v passed is decoded into when reading the claims.
func parseFullClaim(claim string, key *ecdsa.PublicKey, v any) error {
	tok, err := jwt.ParseSigned(claim, []jose.SignatureAlgorithm{jose.ES384})
	if err != nil {
		return fmt.Errorf("error parsing signed token: %w", err)
	}
	var m map[string]any
	if err := tok.Claims(key, v, &m); err != nil {
		return fmt.Errorf("error verifying claims of token: %w", err)
	}
	newKey, present := m["identityPublicKey"]
	if present {
		if err := parseAsKey(newKey, key); err != nil {
			return fmt.Errorf("error parsing identity public key: %w", err)
		}
	}
	return nil
}

// parseAsKey parses the base64 encoded ecdsa.PublicKey held in k as a public key and sets it to the variable
// pub passed.
func parseAsKey(k any, pub *ecdsa.PublicKey) error {
	kStr, _ := k.(string)
	if err := ParsePublicKey(kStr, pub); err != nil {
		return fmt.Errorf("error parsing public key: %w", err)
	}
	return nil
}

// Encode encodes a login request using the encoded login chain passed and the client data. The request's
// client data token is signed using the private key passed. It must be the same as the one used to get the
// login chain. The multiplayer token is used as the Token field in the connection request.
func Encode(loginChain string, data ClientData, key *ecdsa.PrivateKey, token string, legacy bool) []byte {
	// We first decode the login chain we actually got in a new certificate.
	cert := &certificate{}
	_ = json.Unmarshal([]byte(loginChain), &cert)

	// We parse the header of the first claim it has in the chain, which will soon be the second claim.
	keyData := MarshalPublicKey(&key.PublicKey)
	tok, _ := jwt.ParseSigned(cert.Chain[0], []jose.SignatureAlgorithm{jose.ES384})

	//lint:ignore S1005 Double assignment is done explicitly to prevent panics.
	x5uData, _ := tok.Headers[0].ExtraHeaders["x5u"]
	x5u, _ := x5uData.(string)
	claims := jwt.Claims{
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour * 6)),
		NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Hour * 6)),
	}

	signer, _ := jose.NewSigner(jose.SigningKey{Key: key, Algorithm: jose.ES384}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{"x5u": keyData},
	})
	firstJWT, _ := jwt.Signed(signer).Claims(identityPublicKeyClaims{
		Claims:               claims,
		IdentityPublicKey:    x5u,
		CertificateAuthority: true,
	}).Serialize()

	req := &request{
		Certificate: certificate{
			// We add our own claim at the start of the chain.
			Chain: append(chain{firstJWT}, cert.Chain...),
		},
		Token:  token,
		Legacy: legacy,
	}
	// We create another token this time, which is signed the same as the claim we just inserted in the chain,
	// just now it contains client data.
	req.RawToken, _ = jwt.Signed(signer).Claims(data).Serialize()

	return encodeRequest(req)
}

// encodeRequest encodes the request passed to a byte slice which is suitable for setting to the Connection
// Request field in a Login packet.
func encodeRequest(req *request) []byte {
	chainBytes, _ := json.Marshal(req)

	buf := bytes.NewBuffer(nil)
	_ = binary.Write(buf, binary.LittleEndian, int32(len(chainBytes)))
	_, _ = buf.WriteString(string(chainBytes))

	_ = binary.Write(buf, binary.LittleEndian, int32(len(req.RawToken)))
	_, _ = buf.WriteString(req.RawToken)
	return buf.Bytes()
}

// EncodeOffline creates a login request using the identity data and client data passed.
// The private key passed will be used to self-sign the JWTs.
//
// When legacy is true, a self-signed chain with extraData is produced for pre-1.26.10
// servers. When false, a self-signed OIDC multiplayer token is produced with a dummy
// certificate chain.
func EncodeOffline(identityData IdentityData, data ClientData, key *ecdsa.PrivateKey, legacy bool) []byte {
	keyData := MarshalPublicKey(&key.PublicKey)
	claims := jwt.Claims{
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour * 6)),
		NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Hour * 6)),
	}

	signer, _ := jose.NewSigner(jose.SigningKey{Key: key, Algorithm: jose.ES384}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{"x5u": keyData},
	})

	req := &request{AuthenticationType: 2}
	if legacy {
		chainJWT, _ := jwt.Signed(signer).Claims(identityClaims{
			Claims:            claims,
			ExtraData:         identityData,
			IdentityPublicKey: keyData,
		}).Serialize()
		req.Certificate = certificate{Chain: chain{chainJWT}}
		req.Legacy = true
	} else {
		req.Certificate = certificate{Chain: chain{""}}
		req.Token, _ = jwt.Signed(signer).Claims(tokenClaims{
			Claims:          claims,
			ClientPublicKey: keyData,
			XUID:            identityData.XUID,
			DisplayName:     identityData.DisplayName,
			Identity:        identityData.Identity,
			PlayFabID:       identityData.PlayFabID,
			PlayFabTitleID:  identityData.PlayFabTitleID,
		}).Serialize()
	}
	// We create another token this time, which is signed the same as the claim we just inserted in the chain,
	// just now it contains client data.
	req.RawToken, _ = jwt.Signed(signer).Claims(data).Serialize()

	return encodeRequest(req)
}

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
	if _, err := verifier.Verify(context.Background(), raw); err != nil {
		return claims, nil, false, fmt.Errorf("verify ID token: %w", err)
	}
	if err := claims.Validate(jwt.Expected{Time: now}); err != nil {
		return claims, nil, false, fmt.Errorf("validate ID token: %w", err)
	}
	return claims, key, tok.Headers[0].KeyID == "host", nil
}

// identityData selects the platform identity or resolves the client's fallback UUID and name.
func (tc tokenClaims) identityData(data ClientData, selfSigned, trustedHost bool) (IdentityData, error) {
	if selfSigned {
		// Only the offline UUID contributes to identity resolution in a self-signed token.
		tc = tokenClaims{Identity: tc.Identity}
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

// identityClaims holds the claims for the last token in the chain, which contains the IdentityData of the
// player.
type identityClaims struct {
	jwt.Claims

	// ExtraData holds the extra data of this claim, which is the IdentityData of the player.
	ExtraData IdentityData `json:"extraData"`

	IdentityPublicKey string `json:"identityPublicKey"`
}

// Validate validates the identity claims held by the struct and returns an error if any illegal data was
// encountered.
func (c identityClaims) Validate(e jwt.Expected) error {
	if err := c.Claims.Validate(e); err != nil {
		return err
	}
	return c.ExtraData.Validate()
}

// identityPublicKeyClaims holds the claims for a JWT that holds an identity public key.
type identityPublicKeyClaims struct {
	jwt.Claims

	// IdentityPublicKey holds a serialised ecdsa.PublicKey used in the next JWT in the chain.
	IdentityPublicKey    string `json:"identityPublicKey"`
	CertificateAuthority bool   `json:"certificateAuthority,omitempty"`
}

// ParsePublicKey parses an ecdsa.PublicKey from the base64 encoded public key data passed and sets it to a
// pointer. If parsing failed or if the public key was not of the type ECDSA, an error is returned.
func ParsePublicKey(b64Data string, key *ecdsa.PublicKey) error {
	data, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return fmt.Errorf("decode public key data: %w", err)
	}
	publicKey, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("expected ECDSA public key, got %v", key)
	}
	*key = *ecdsaKey
	return nil
}

// MarshalPublicKey marshals an ecdsa.PublicKey to a base64 encoded binary representation.
func MarshalPublicKey(key *ecdsa.PublicKey) string {
	data, _ := x509.MarshalPKIXPublicKey(key)
	return base64.StdEncoding.EncodeToString(data)
}
