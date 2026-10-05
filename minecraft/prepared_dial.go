package minecraft

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

var (
	// ErrPreparedDialNotReady means preparation has not completed successfully. Commit never waits for it.
	ErrPreparedDialNotReady = errors.New("prepared dial is not ready")
	// ErrPreparedDialMismatch means the address, protocol, account generation or transport settings changed.
	ErrPreparedDialMismatch = errors.New("prepared dial does not match the current dial")
	// ErrPreparedDialClaimed means the preparation has already been committed.
	ErrPreparedDialClaimed = errors.New("prepared dial has already been claimed")
	// ErrPreparedDialUnsupported means the transport needs authentication before it can be dialed.
	ErrPreparedDialUnsupported = errors.New("transport does not support deferred login preparation")
)

// PreparedDial owns one fresh private key, its verified multiplayer token, and a negotiated transport.
// Preparation sends RequestNetworkSettings only. Login and all subsequent actions require CommitContext.
type PreparedDial struct {
	mu                sync.Mutex
	dialer            Dialer
	address           string
	accountGeneration uint64
	key               *ecdsa.PrivateKey
	authentication    dialAuthentication
	expires           time.Time
	conn              *Conn
	ctx               context.Context
	cancel            context.CancelCauseFunc
	done              chan struct{}
	claimed           chan struct{}
	settingsReady     chan struct{}
	connected         chan struct{}
	listenerDone      chan struct{}
	err               error
	complete          bool
	closed            bool
	committed         bool
	live              atomic.Bool
}

// PrepareContextNetwork concurrently prepares authentication and settings without Login on an identity-independent transport.
// ctx owns unclaimed lifetime; accountGeneration identifies an account lifecycle; protocol/flush/decompression stay frozen.
func (d Dialer) PrepareContextNetwork(ctx context.Context, network Network, address string, accountGeneration uint64) (*PreparedDial, error) {
	if network == nil || address == "" || accountGeneration == 0 {
		return nil, ErrPreparedDialMismatch
	}
	if _, ok := network.(identityDialer); ok {
		return nil, ErrPreparedDialUnsupported
	}
	if _, ok := network.(identityProviderDialer); ok {
		return nil, ErrPreparedDialUnsupported
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d = d.normalized()
	if d.TokenSource != nil || d.XBLClient != nil {
		ctx = auth.WithContextClient(ctx, d.HTTPClient)
	}
	key, err := ecdsa.GenerateKey(elliptic.P384(), cryptorand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate preparation key: %w", err)
	}
	ctx, cancel := context.WithCancelCause(ctx)
	p := &PreparedDial{
		dialer: d, address: address, accountGeneration: accountGeneration, key: key,
		ctx: ctx, cancel: cancel, done: make(chan struct{}), claimed: make(chan struct{}),
		settingsReady: make(chan struct{}), connected: make(chan struct{}),
	}
	go p.prepare(network)
	go func() {
		select {
		case <-p.ctx.Done():
			_ = p.Close()
		case <-p.claimed:
		}
	}()
	return p, nil
}

// Done closes when authentication and settings negotiation have both finished, including failure.
func (p *PreparedDial) Done() <-chan struct{} { return p.done }

// Ready reports whether a healthy, unclaimed preparation can be committed immediately.
func (p *PreparedDial) Ready() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ready()
}

func (p *PreparedDial) ready() bool {
	return p.complete && p.err == nil && !p.closed && !p.committed && p.ctx.Err() == nil &&
		p.conn != nil && p.conn.ctx.Err() == nil && (p.expires.IsZero() || time.Now().Before(p.expires))
}

// Err returns the preparation failure, if any. It does not wait for completion.
func (p *PreparedDial) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	if p.closed {
		return context.Cause(p.ctx)
	}
	if p.conn != nil && p.conn.ctx.Err() != nil {
		return p.conn.closeErr("prepare")
	}
	return nil
}

// Close cancels and joins an unclaimed preparation. Once committed, ownership belongs to the caller
// and Close or cancellation/expiry of the preparation context never closes the retained Conn.
func (p *PreparedDial) Close() error {
	p.mu.Lock()
	if p.committed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.cancel(context.Canceled)
	conn := p.conn
	p.mu.Unlock()
	if conn != nil {
		_ = conn.abort(context.Cause(p.ctx))
	}
	<-p.done
	p.mu.Lock()
	listenerDone := p.listenerDone
	p.mu.Unlock()
	if listenerDone != nil {
		<-listenerDone
	}
	return nil
}

func (p *PreparedDial) prepare(network Network) {
	results := make(chan error, 2)
	go func() {
		authentication, err := p.dialer.authenticate(p.ctx, p.key)
		authentication.close()
		authentication.release, authentication.ctx = nil, nil
		var expires time.Time
		if err == nil && authentication.token != "" {
			expires, err = verifiedTokenBinding(authentication.token, &p.key.PublicKey)
		}
		p.mu.Lock()
		p.authentication, p.expires = authentication, expires
		p.mu.Unlock()
		results <- err
	}()
	go func() { results <- p.prepareTransport(network) }()
	for range 2 {
		if err := <-results; err != nil {
			p.mu.Lock()
			if p.err == nil {
				p.err = err
			}
			conn := p.conn
			p.cancel(err)
			p.mu.Unlock()
			if conn != nil {
				_ = conn.abort(err)
			}
		}
	}
	p.mu.Lock()
	p.complete = true
	close(p.done)
	p.mu.Unlock()
}

func (p *PreparedDial) prepareTransport(network Network) error {
	netConn, err := network.DialContext(p.ctx, p.address)
	if err != nil {
		return err
	}
	conn := newConn(netConn, p.key, p.dialer.ErrorLog, p.dialer.Protocol, p.dialer.FlushRate, false)
	conn.pool = serverPacketPool(conn.proto, false)
	conn.maxDecompressedLen = p.dialer.MaxDecompressedLen
	conn.disconnectOnInvalidPacket = true
	p.mu.Lock()
	p.conn, p.listenerDone = conn, make(chan struct{})
	if p.ctx.Err() != nil {
		close(p.listenerDone)
		p.mu.Unlock()
		_ = conn.abort(context.Cause(p.ctx))
		return context.Cause(p.ctx)
	}
	p.mu.Unlock()
	go p.listen()
	if err := conn.WritePacket(&packet.RequestNetworkSettings{ClientProtocol: conn.proto.ID()}); err != nil {
		return fmt.Errorf("send prepared network settings request: %w", err)
	}
	if err := conn.Flush(); err != nil {
		return err
	}
	select {
	case <-p.ctx.Done():
		return context.Cause(p.ctx)
	case <-conn.ctx.Done():
		return conn.closeErr("prepare")
	case <-p.settingsReady:
		return nil
	}
}

// verifiedTokenBinding reads only an immutable token already verified by authenticate.
func verifiedTokenBinding(token string, key *ecdsa.PublicKey) (time.Time, error) {
	tok, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES384, jose.RS256})
	if err != nil {
		return time.Time{}, err
	}
	var claims struct {
		jwt.Claims
		PublicKey string `json:"cpk"`
	}
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return time.Time{}, err
	}
	var bound ecdsa.PublicKey
	if err := login.ParsePublicKey(claims.PublicKey, &bound); err != nil || !key.Equal(&bound) {
		return time.Time{}, errors.New("multiplayer token does not match the preparation key")
	}
	if claims.Expiry == nil || !time.Now().Before(claims.Expiry.Time()) {
		return time.Time{}, errors.New("prepared multiplayer token is expired")
	}
	return claims.Expiry.Time(), nil
}

// CommitContext claims a ready preparation once with current client data/callbacks and the same nonzero account generation.
// Mismatched, unfinished, failed or expired preparations return immediately without sending Login.
func (p *PreparedDial) CommitContext(ctx context.Context, d Dialer, address string, accountGeneration uint64) (conn *Conn, err error) {
	d = d.normalized()
	p.mu.Lock()
	if p.committed {
		p.mu.Unlock()
		return nil, ErrPreparedDialClaimed
	}
	if address != p.address || accountGeneration != p.accountGeneration ||
		!reflect.DeepEqual(d.Protocol, p.dialer.Protocol) || d.FlushRate != p.dialer.FlushRate ||
		d.MaxDecompressedLen != p.dialer.MaxDecompressedLen ||
		(d.TokenSource != nil || d.XBLClient != nil) != (p.dialer.TokenSource != nil || p.dialer.XBLClient != nil) {
		p.mu.Unlock()
		return nil, ErrPreparedDialMismatch
	}
	if err := ctx.Err(); err != nil {
		p.mu.Unlock()
		return nil, err
	}
	if !p.ready() {
		p.mu.Unlock()
		return nil, ErrPreparedDialNotReady
	}
	p.committed = true
	close(p.claimed)
	conn = p.conn
	identity := p.authentication.identityData
	if p.authentication.token == "" {
		identity = d.IdentityData
	}
	d.configureConn(conn, identity)
	defaultIdentityData(&conn.identityData)
	if conn.clientData.GameVersion == "" {
		conn.clientData.GameVersion = d.Protocol.Ver()
	}
	defaultClientData(address, conn.identityData.DisplayName, &conn.clientData)
	var request []byte
	if p.authentication.token == "" {
		if !d.KeepXBLIdentityData {
			clearXBLIdentityData(&conn.identityData)
		}
		request = login.EncodeOffline(conn.identityData, conn.clientData, p.key)
	} else {
		setAndroidData(&conn.clientData)
		request = login.EncodeToken(conn.clientData, p.key, p.authentication.token)
	}
	conn.expect(packet.IDResourcePacksInfo, packet.IDServerToClientHandshake, packet.IDPlayStatus, packet.IDStartGame)
	abortDone := make(chan struct{})
	stopAbort := context.AfterFunc(ctx, func() {
		_ = conn.abort(context.Cause(ctx))
		close(abortDone)
	})
	if err = conn.WritePacket(&packet.Login{ConnectionRequest: request, ClientProtocol: d.Protocol.ID()}); err == nil {
		err = conn.Flush()
	}
	p.live.Store(true)
	p.authentication, p.dialer, p.key = dialAuthentication{}, Dialer{}, nil
	p.mu.Unlock()
	if !stopAbort() {
		<-abortDone
	}
	if ctx.Err() != nil {
		err = context.Cause(ctx)
	}
	if err != nil {
		_ = conn.abort(err)
		return nil, conn.wrap(err, "dial")
	}
	select {
	case <-ctx.Done():
		err = conn.wrap(context.Cause(ctx), "dial")
	case <-conn.ctx.Done():
		err = conn.closeErr("dial")
	case <-p.connected:
		if ctx.Err() != nil {
			err = conn.wrap(context.Cause(ctx), "dial")
		} else if conn.ctx.Err() != nil {
			err = conn.closeErr("dial")
		} else {
			return conn, nil
		}
	}
	_ = conn.abort(err)
	return nil, err
}
